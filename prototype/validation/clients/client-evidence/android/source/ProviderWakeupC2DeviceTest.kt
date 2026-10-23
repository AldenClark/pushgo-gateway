package io.ethan.pushgo

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.ethan.pushgo.data.*
import io.ethan.pushgo.data.db.PushGoDatabase
import io.ethan.pushgo.notifications.MessageStateCoordinator
import io.ethan.pushgo.notifications.ProviderIngressCoordinator
import io.ethan.pushgo.notifications.InboundMessageProcessor
import io.ethan.pushgo.notifications.InboundProcessorRuntimeResolver
import io.ethan.pushgo.notifications.DefaultInboundProcessorRuntime
import io.ethan.pushgo.notifications.ProviderAckDrainCoordinator
import java.net.ServerSocket
import java.net.SocketException
import java.util.Collections
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProviderWakeupC2DeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var db: PushGoDatabase
    private lateinit var settings: SettingsRepository
    private lateinit var messages: MessageRepository
    private lateinit var entities: EntityRepository
    private lateinit var ledger: InboundDeliveryLedgerRepository
    private lateinit var channels: ChannelSubscriptionRepository
    private val secrets = MemorySecrets()
    private val servers = mutableListOf<Gateway>()

    @Before fun setUp() { context.deleteDatabase(DB_NAME); open() }
    @After fun tearDown() {
        servers.forEach { it.close() }
        db.close()
        context.deleteDatabase(DB_NAME)
        context.getSharedPreferences(DB_NAME, Context.MODE_PRIVATE).edit().clear().commit()
    }

    /** Ordinary message only. The runtime resolver binds an isolated on-disk Room DB;
     * omitted hooksFactory means production default hooks, parser, persistence, HTTP and ACK.
     * Purpose: preserve the message represented by a provider wakeup. Independent defects:
     * wakeup handled as direct payload; lost filter; has_more pulling unrelated page;
     * premature ACK before content/outbox commit; recovery losing canonical content.
     * Native Room + HttpURLConnection cannot be replaced by protocol JVM imports.
     * Cost: three methods, 8 loopback requests, no activity, Event/Thing, watch or real FCM.
     */
    @Test
    fun wakeupDefaultHooksFilterPersistAckAndSurviveReopen() = runBlocking {
        val id = "c2-wakeup-success"
        val gateway = gateway { path, body -> when (path) {
            PULL -> {
                assertEquals(id, body.getString("delivery_id"))
                assertEquals("device-a", body.getString("device_key"))
                200 to page(id, hasMore = true)
            }
            ACK -> {
                assertAckAfterCommit(id, body)
                200 to ackReceipt()
            }
            else -> error("Wakeup escaped V2: $path")
        } }
        configure(gateway)
        processWakeup(id)
        assertEquals(listOf(PULL, ACK), gateway.paths())
        assertEquals("acked", ackState(id))
        assertEquals(0, sqlCount("inbound_delivery_ack_outbox"))
        assertEquals(0, sqlCount("messages", "message_id = 'transport-wakeup-only'"))
        assertEquals(0, sqlCount("legacy_provider_ingress"))
        db.close(); open()
        assertEquals(1, sqlCount("messages"))
        assertCanonical(id)
        assertEquals("acked", ackState(id))
        gateway.assertHealthy()
    }

    @Test
    fun wakeupCanonicalSqlFailureNeverAcksAndRetryPersistsOnce() = runBlocking {
        val id = "c2-wakeup-sql-retry"
        val gateway = gateway { path, body -> when (path) {
            PULL -> {
                assertEquals(id, body.getString("delivery_id"))
                200 to page(id, hasMore = true)
            }
            ACK -> { assertAckAfterCommit(id, body); 200 to ackReceipt() }
            else -> error("Wakeup escaped V2: $path")
        } }
        configure(gateway)
        rejectMessageWrites()
        assertNotNull(runCatching { processWakeup(id) }.exceptionOrNull())
        assertEquals(listOf(PULL), gateway.paths())
        assertEquals(0, sqlCount("messages"))
        assertEquals(0, sqlCount("inbound_delivery_ledger"))
        assertEquals(0, sqlCount("inbound_delivery_ack_outbox"))
        db.close(); open()
        db.openHelper.writableDatabase.execSQL("DROP TRIGGER reject_provider_write")
        processWakeup(id)
        assertEquals(listOf(PULL, PULL, ACK), gateway.paths())
        db.close(); open()
        assertEquals(1, sqlCount("messages"))
        assertCanonical(id)
        assertEquals("acked", ackState(id))
        gateway.assertHealthy()
    }

    @Test
    fun wakeupFailedAckOutboxSurvivesReopenAndDrainsCapturedIdentity() = runBlocking {
        val id = "c2-wakeup-ack-retry"
        var ackCalls = 0
        val gateway = gateway { path, body -> when (path) {
            PULL -> {
                assertEquals(id, body.getString("delivery_id"))
                200 to page(id, hasMore = true)
            }
            ACK -> {
                ackCalls++
                assertAckAfterCommit(id, body)
                if (ackCalls == 1) 503 to JSONObject().put("success", false)
                    .put("error_code", "c2_retryable_ack_failure")
                else 200 to ackReceipt()
            }
            else -> error("Wakeup escaped V2: $path")
        } }
        configure(gateway)
        assertNotNull(runCatching { processWakeup(id) }.exceptionOrNull())
        assertEquals(listOf(PULL, ACK), gateway.paths())
        assertEquals("pending", ackState(id))
        assertEquals(1, sqlCount("inbound_delivery_ack_outbox"))
        db.close(); open()
        assertCanonical(id)
        assertEquals("pending", ackState(id))
        val pending = ledger.loadPendingAcks()
        assertEquals(1, pending.size)
        assertEquals(gateway.baseUrl, pending.single().gatewayUrl)
        assertEquals("device-a", pending.single().deviceKey)
        assertEquals(id, pending.single().deliveryId)
        assertEquals(1, pending.single().attemptCount)
        // Change current configuration; the durable record must own the recovery target.
        val replacement = gateway { path, _ -> error("Recovery escaped to current config: $path") }
        settings.setServerAddress(replacement.baseUrl)
        settings.setDeviceKey("device-b")
        val recovered = ProviderAckDrainCoordinator.drainPendingAcks(
            loadPendingAcks = ledger::loadFairPendingAcks,
            beginAttempt = ledger::beginAckAttempt,
            ackMessages = channels::ackMessages,
            markAcked = ledger::markAckRecordsAcked,
        )
        assertFalse(recovered.hasFailures)
        assertEquals(listOf(id), recovered.ackedIds)
        assertTrue(replacement.paths().isEmpty())
        assertEquals(listOf(PULL, ACK, ACK), gateway.paths())
        db.close(); open()
        assertEquals(1, sqlCount("messages"))
        assertCanonical(id)
        assertEquals("acked", ackState(id))
        assertEquals(0, sqlCount("inbound_delivery_ack_outbox"))
        gateway.assertHealthy(); replacement.assertHealthy()
    }

    private suspend fun processWakeup(id: String) {
        InboundMessageProcessor(runtimeResolver = InboundProcessorRuntimeResolver {
            DefaultInboundProcessorRuntime(channels, messages, entities, ledger, settings)
        }).process(context, mapOf("provider_wakeup" to "1", "delivery_id" to id), "transport-wakeup-only")
    }

    private fun assertAckAfterCommit(id: String, body: JSONObject) {
        assertEquals("device-a", body.getString("device_key"))
        assertEquals(listOf(id), body.getJSONArray("delivery_ids").let { a -> (0 until a.length()).map(a::getString) })
        assertCanonical(id)
        assertEquals(1, sqlCount("messages"))
        assertEquals("pending", ackState(id))
        assertEquals(1, sqlCount("inbound_delivery_ack_outbox"))
    }

    private suspend fun configure(gateway: Gateway) {
        settings.setServerAddress(gateway.baseUrl)
        settings.setUseFcmChannel(false)
        settings.setDeviceKey("device-a")
    }

    private fun open() {
        db = PushGoDatabase.buildForTest(context, DB_NAME)
        settings = SettingsRepository(db.appSettingsDao(), secrets,
            context.getSharedPreferences(DB_NAME, Context.MODE_PRIVATE))
        messages = MessageRepository(db, db.messageDao(), db.messageChannelStatsDao(), db.messageMetadataIndexDao(),
            db.inboundDeliveryLedgerDao(), db.operationLedgerDao(), db.thingHeadDao(), db.thingSubMessageDao(), db.pendingThingMessageDao())
        entities = EntityRepository(db, db.inboundDeliveryLedgerDao(), db.operationLedgerDao(), db.eventChangeLogDao(),
            db.thingChangeLogDao(), db.thingSubEventDao(), db.topLevelEventHeadDao(), db.thingHeadDao(), db.thingSubMessageDao())
        ledger = InboundDeliveryLedgerRepository(db, db.inboundDeliveryLedgerDao(), db.inboundDeliveryAckOutboxDao(), db.legacyProviderIngressDao())
        channels = ChannelSubscriptionRepository(ChannelSubscriptionStore(db.channelSubscriptionDao(), secrets), settings,
            MessageStateCoordinator(context, messages), messages, entities, db,
            object : PushTokenProvider { override suspend fun fetchToken(timeoutMs: Long): String? = null })
    }

    private fun rejectMessageWrites() = db.openHelper.writableDatabase.execSQL(
        "CREATE TRIGGER reject_provider_write BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'provider canonical store failure'); END")

    private fun sqlCount(table: String, condition: String = "1 = 1"): Int = db.openHelper.readableDatabase
        .query("SELECT count(*) FROM $table WHERE $condition").use { cursor -> cursor.moveToFirst(); cursor.getInt(0) }

    private fun assertCanonical(id: String) {
        val content = db.openHelper.readableDatabase.query(
            "SELECT title, body FROM messages WHERE message_id = ?", arrayOf(id),
        ).use { cursor ->
            assertTrue("Canonical message $id missing", cursor.moveToFirst())
            listOf(cursor.getString(0), cursor.getString(1))
        }
        assertEquals(listOf("retained-$id", "canonical-body-$id"), content)
    }

    private fun ackState(id: String): String? = db.openHelper.readableDatabase
        .query("SELECT ack_state FROM inbound_delivery_ledger WHERE delivery_id = ?", arrayOf(id))
        .use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }

    private fun payload(id: String) = JSONObject().put("entity_type", "message").put("message_id", id)
        .put("title", "retained-$id").put("body", "canonical-body-$id").put("delivery_id", "payload-spoof")
        .put("ttl", "1") // Already expired alerts still persist and settle, without OS notification dependence.

    private fun page(id: String, hasMore: Boolean) = JSONObject().put("success", true).put("data", JSONObject()
        .put("items", JSONArray().put(JSONObject().put("delivery_id", id).put("payload", payload(id))))
        .put("has_more", hasMore))

    private fun ackReceipt() = JSONObject().put("success", true).put("data", JSONObject()
        .put("requested_count", 1).put("removed_count", 1))

    private fun gateway(handler: (String, JSONObject) -> Pair<Int, JSONObject>): Gateway = Gateway(handler).also { servers += it }

    private class Gateway(val handler: (String, JSONObject) -> Pair<Int, JSONObject>) : AutoCloseable {
        private val socket = ServerSocket(0)
        val baseUrl = "http://127.0.0.1:${socket.localPort}"
        private val paths = Collections.synchronizedList(mutableListOf<String>())
        private val failure = AtomicReference<Throwable?>()
        private val worker = thread(name = "provider-v2-native-gateway", isDaemon = true) {
            while (!socket.isClosed) {
                try {
                    socket.accept().use { connection ->
                        connection.soTimeout = 5_000
                        val reader = connection.getInputStream().bufferedReader()
                        val path = reader.readLine().split(' ')[1]
                        var length = 0
                        while (true) {
                            val header = reader.readLine() ?: break
                            if (header.isEmpty()) break
                            if (header.startsWith("Content-Length:", true)) length = header.substringAfter(':').trim().toInt()
                        }
                        val content = CharArray(length)
                        var read = 0
                        while (read < length) { val n = reader.read(content, read, length - read); check(n >= 0); read += n }
                        paths += path
                        val response = try { handler(path, JSONObject(String(content))) } catch (error: Throwable) {
                            failure.compareAndSet(null, error)
                            500 to JSONObject().put("success", false).put("error", "test request oracle failed")
                        }
                        val bytes = response.second.toString().toByteArray()
                        connection.getOutputStream().apply {
                            write("HTTP/1.1 ${response.first} Test\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray())
                            write(bytes); flush()
                        }
                    }
                } catch (error: Throwable) { if (!socket.isClosed && error !is SocketException) failure.compareAndSet(null, error) }
            }
        }
        fun paths(): List<String> = synchronized(paths) { paths.toList() }
        fun assertHealthy() { failure.get()?.let { throw AssertionError("Gateway request oracle failed", it) } }
        override fun close() { socket.close(); worker.join(1_000); assertHealthy() }
    }

    private class MemorySecrets : SecureSecretStore {
        private val values = mutableMapOf<String, String?>()
        private var key: ByteArray? = null
        override fun gatewayToken() = values["gateway"]
        override fun setGatewayToken(token: String?) { values["gateway"] = token }
        override fun gatewayAckToken(gatewayUrl: String) = values["ack:$gatewayUrl"]
        override fun setGatewayAckToken(gatewayUrl: String, token: String?) { values["ack:$gatewayUrl"] = token }
        override fun fcmToken() = values["fcm"]
        override fun setFcmToken(token: String?) { values["fcm"] = token }
        override fun gatewayTransitionJournal() = values["journal"]
        override fun setGatewayTransitionJournal(journal: String?) { values["journal"] = journal }
        override fun deviceKey() = values["device"]
        override fun setDeviceKey(deviceKey: String?) { values["device"] = deviceKey }
        override fun notificationKeyBytes() = key
        override fun setNotificationKeyBytes(value: ByteArray?) { key = value }
        override fun channelPassword(gatewayUrl: String, channelId: String) = values["channel:$gatewayUrl:$channelId"]
        override fun setChannelPassword(gatewayUrl: String, channelId: String, password: String?) { values["channel:$gatewayUrl:$channelId"] = password }
        override fun removeChannelPassword(gatewayUrl: String, channelId: String) { values.remove("channel:$gatewayUrl:$channelId") }
        override fun clearAll() { values.clear(); key = null }
    }

    companion object {
        private const val DB_NAME = "provider_wakeup_c2_native.db"
        private const val PULL = "/v2/messages/pull"
        private const val ACK = "/v2/messages/ack"
    }
}
