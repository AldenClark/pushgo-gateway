package io.ethan.pushgo

import android.content.Context
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.ethan.pushgo.data.*
import io.ethan.pushgo.data.db.PushGoDatabase
import io.ethan.pushgo.notifications.*
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.async
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.cancelAndJoin
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Two separately launched native test processes. The host must force-stop the owned
 * .c3evidence package and verify no PID between these methods. Only provider transport
 * is captured and injected; HTTP/controller/parser/Room/Keystore/ACK are production. */
@RunWith(AndroidJUnit4::class)
class CandidateOrdinaryC3DeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val args get() = InstrumentationRegistry.getArguments()
    private val session get() = File(context.filesDir,"c3-session.json")
    private val trace get() = File(context.filesDir,"c3-network.jsonl")
    private val fixture get() = args.getString("c3MockUrl") ?: error("c3MockUrl required")
    private lateinit var db: PushGoDatabase
    private lateinit var settings: SettingsRepository
    private lateinit var messages: MessageRepository
    private lateinit var entities: EntityRepository
    private lateinit var ledger: InboundDeliveryLedgerRepository
    private lateinit var channels: ChannelSubscriptionRepository
    private lateinit var network: CandidateNetworkBoundary
    private lateinit var state: JSONObject
    private val providerToken get() = state.getString("provider_token")
    private val channelId get() = state.getString("channel_id")
    private val channelCredential get() = state.getString("channel_credential")

    @Before fun open() {
        db = PushGoDatabase.buildForTest(context,DB_NAME)
        val secrets = AndroidKeystoreSecretStore(context,"c3_keystore_preferences")
        settings = SettingsRepository(db.appSettingsDao(), secrets,
            context.getSharedPreferences("c3_settings_cache",Context.MODE_PRIVATE))
        messages = MessageRepository(db,db.messageDao(),db.messageChannelStatsDao(),db.messageMetadataIndexDao(),
            db.inboundDeliveryLedgerDao(),db.operationLedgerDao(),db.thingHeadDao(),db.thingSubMessageDao(),db.pendingThingMessageDao())
        entities = EntityRepository(db,db.inboundDeliveryLedgerDao(),db.operationLedgerDao(),db.eventChangeLogDao(),
            db.thingChangeLogDao(),db.thingSubEventDao(),db.topLevelEventHeadDao(),db.thingHeadDao(),db.thingSubMessageDao())
        ledger = InboundDeliveryLedgerRepository(db,db.inboundDeliveryLedgerDao(),db.inboundDeliveryAckOutboxDao(),db.legacyProviderIngressDao())
        channels = ChannelSubscriptionRepository(ChannelSubscriptionStore(db.channelSubscriptionDao(),secrets),settings,
            MessageStateCoordinator(context,messages),messages,entities,db,
            object : PushTokenProvider { override suspend fun fetchToken(timeoutMs: Long): String? = if (::state.isInitialized) providerToken else null })
        network = CandidateNetworkBoundary(args.getString("c3GatewayUrl") ?: error("c3GatewayUrl required"),URL(args.getString("c3PublicUrl") ?: error("c3PublicUrl required")).port,trace) { body ->
            val ids=body.optJSONArray("delivery_ids") ?: org.json.JSONArray().put(body.getString("delivery_id"))
            for (i in 0 until ids.length()) {
                val id=ids.getString(i)
                assertEquals("pending",ackState(id))
                assertEquals(1, count("inbound_delivery_ack_outbox","delivery_id = '$id'"))
                assertEquals(1, count("inbound_delivery_ledger","delivery_id = '$id'"))
                val canonical=db.openHelper.readableDatabase.query("SELECT count(*) FROM messages m JOIN inbound_delivery_ledger l ON l.entity_id=m.message_id WHERE l.delivery_id=?",arrayOf(id)).use { it.moveToFirst();it.getInt(0) }
                assertEquals("this delivery canonical row must commit before its ACK",1,canonical)
            }
        }
    }
    @After fun close() { network.close(); db.close() }

    @Test fun phase1OrdinaryLoopAndPersistUnknownAck() = runBlocking {
        check(!session.exists()) { "C3 phase1 must start from clean owned app data" }
        state=JSONObject().put("phase1_pid",Process.myPid()).put("provider_token","c3-android-${System.nanoTime()}")
            .put("channel_credential", "c3-synthetic-"+System.nanoTime())
        settings.setServerAddress(network.baseUrl)
        settings.setUseFcmChannel(true)
        val auth=args.getString("c3GatewayAuth")?.takeIf { it.isNotBlank() }
        if (auth!=null) settings.setGatewayToken(auth)
        settings.setFcmToken(providerToken)
        val device=channels.syncProviderDeviceToken(providerToken)
        check(device.isNotBlank()); state.put("device_key",device)
        val subscribed=channels.createChannel("C3 Android ordinary",channelCredential,providerToken)
        assertTrue(subscribed.subscribed); state.put("channel_id",subscribed.channelId)
        assertEquals(1,channels.loadSubscriptions().size)
        channels.renameChannel(channelId,"C3 Android renamed")
        channels.syncSubscriptionsIfNeeded(providerToken)
        assertEquals("C3 Android renamed",channels.loadSubscriptions().single().displayName)
        assertEquals(channelCredential,channels.channelPassword(channelId))
        // Lost sync response races a real delivery: remote sync committed, client operation interrupted.
        network.prepareResponseHold("/channel/sync")
        val interruptedSync=async(Dispatchers.IO) { channels.syncSubscriptionsIfNeeded(providerToken) }
        withContext(Dispatchers.IO) { network.awaitHeld() }
        val duringSync=sendAndCapture("during-sync","c3-during-sync-content")
        process(duringSync); assertFalse(drain().hasFailures); assertBody("c3-during-sync-content")
        interruptedSync.cancel(); network.releaseHeld(); interruptedSync.join()
        assertTrue(interruptedSync.isCancelled)
        channels.syncSubscriptionsIfNeeded(providerToken)
        assertEquals("C3 Android renamed",channels.loadSubscriptions().single().displayName)
        // Direct delivery uses the actual captured FCM data envelope, not a fabricated payload.
        val direct=sendAndCapture("direct","c3-direct-content",hold=true)
        assertFalse(isWakeup(direct))
        process(direct)
        assertFalse(drain().hasFailures)
        assertBody("c3-direct-content")
        assertEquals(0,count("inbound_delivery_ack_outbox"))
        val finished=request(fixture,"GET","/__test/requests?token=$providerToken&op_id=${direct.getString("op_id")}&limit=100",null).getJSONArray("requests")
        assertFalse("ACK must complete while exact provider response is still held",(0 until finished.length()).any { finished.getJSONObject(it).optString("event")=="provider_finished" })
        trace.appendText(JSONObject().put("stage","acked_before_provider_receipt").put("delivery_id",direct.getString("delivery_id")).put("pid",Process.myPid()).toString()+"\n")
        val released=request(fixture,"POST","/__test/release",JSONObject().put("provider","fcm").put("token",providerToken).put("op_id",direct.getString("op_id")))
        assertEquals(1,released.getInt("released"))
        process(direct) // exact provider replay must not append a second canonical message.
        assertEquals(2,count("messages"))
        // A real oversized sender payload must be retained at Gateway and projected by filtered V2 Pull.
        val oversizedBody="c3-oversized-"+"x".repeat(7000)
        val wakeup=sendAndCapture("oversized",oversizedBody)
        assertTrue("oversized provider envelope must be a wakeup",isWakeup(wakeup))
        val wakeupId=wakeup.getString("delivery_id")
        val ackBefore=network.requests.count { it.endsWith("/v2/messages/ack") }
        db.openHelper.writableDatabase.execSQL("CREATE TRIGGER c3_reject_write BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'c3 canonical store failure'); END")
        assertNotNull("native SQL failure must escape, not report success",runCatching { process(wakeup) }.exceptionOrNull())
        assertEquals(ackBefore,network.requests.count { it.endsWith("/v2/messages/ack") })
        assertNull(ackState(wakeupId)); assertEquals(2,count("messages"))
        db.openHelper.writableDatabase.execSQL("DROP TRIGGER c3_reject_write")
        process(wakeup)
        assertBody(oversizedBody); assertEquals("acked",ackState(wakeupId))
        assertTrue(channels.pullMessages(wakeupId).items.isEmpty())
        assertTrue("unknown filtered ID cannot pull an unrelated page",channels.pullMessages("00000000000000000000000000000000").items.isEmpty())
        // Unavailable network does not settle a delivery; the real outbox retries the same immutable ID.
        val unavailable=sendAndCapture("unavailable","c3-unavailable-content")
        process(unavailable)
        network.dropAckMode.set("before")
        assertTrue(drain().hasFailures)
        network.dropAckMode.set(null)
        assertEquals("pending",ackState(unavailable.getString("delivery_id")))
        assertEquals(1,ledger.loadPendingAcks().size)
        assertFalse(drain().hasFailures)
        assertEquals("acked",ackState(unavailable.getString("delivery_id")))
        // Network loss after Gateway commits ACK leaves a durable client outbox with unknown result.
        val unknown=sendAndCapture("unknown","c3-unknown-ack-content")
        network.dropAckMode.set("after")
        process(unknown)
        assertTrue("lost ACK receipt must remain a failed drain",drain().hasFailures)
        network.dropAckMode.set(null)
        val unknownId=unknown.getString("delivery_id")
        assertBody("c3-unknown-ack-content")
        assertEquals("pending",ackState(unknownId)); assertEquals(1,ledger.loadPendingAcks().size)
        assertEquals(network.baseUrl,ledger.loadPendingAcks().single().gatewayUrl)
        state.put("unknown_capture",unknown).put("unknown_delivery_id",unknownId)
            .put("canonical_count",count("messages")).put("phase1_complete",true)
        check(session.writeTextAndSync(state.toString()))
        network.assertHealthy()
    }

    @Test fun phase2NewProcessRecoverUnsubscribeAndLogout() = runBlocking {
        state=JSONObject(session.readText())
        assertTrue(state.getBoolean("phase1_complete"))
        assertNotEquals("host must kill the complete app process",state.getInt("phase1_pid"),Process.myPid())
        // Assert on durable storage before any recovery requests.
        assertEquals(network.baseUrl,settings.getServerAddress())
        assertEquals(state.getString("device_key"),settings.getDeviceKey())
        assertEquals(channelCredential,channels.channelPassword(channelId))
        assertEquals("C3 Android renamed",channels.loadSubscriptions().single().displayName)
        assertEquals(state.getInt("canonical_count"),count("messages"))
        assertBody("c3-unknown-ack-content")
        assertEquals(1,ledger.loadPendingAcks().size)
        val outcome=drain()
        assertFalse(outcome.hasFailures)
        assertEquals(0,ledger.loadPendingAcks().size)
        assertEquals("acked",ackState(state.getString("unknown_delivery_id")))
        process(state.getJSONObject("unknown_capture"))
        assertEquals(state.getInt("canonical_count"),count("messages"))
        assertTrue(channels.pullMessages().items.isEmpty())
        val beforeLogout=sendAndCapture("before-logout","c3-before-logout-content")
        network.prepareResponseHold("/channel/device/delete")
        val routeDelete=async(Dispatchers.IO) {
            ChannelSubscriptionService().deleteDeviceChannel(network.baseUrl,settings.getGatewayToken(),state.getString("device_key"),"fcm")
        }
        withContext(Dispatchers.IO) { network.awaitHeld() }
        // This delivery was frozen before deletion. Its original ACK identity must still settle.
        process(beforeLogout); assertFalse(drain().hasFailures); assertBody("c3-before-logout-content")
        routeDelete.cancel();network.releaseHeld();routeDelete.join();assertTrue(routeDelete.isCancelled)
        assertEquals(state.getInt("canonical_count")+1,count("messages"))
        // Reconcile route deliberately through real register/upsert before unsubscribe.
        channels.syncProviderDeviceToken(providerToken)
        channels.unsubscribeChannel(channelId,providerToken)
        assertTrue(channels.loadSubscriptions().isEmpty())
        assertEquals(state.getInt("canonical_count")+1,count("messages"))
        // Real production route cleanup service used by gateway transitions; there is no app logout controller.
        ChannelSubscriptionService().deleteDeviceChannel(network.baseUrl,settings.getGatewayToken(),state.getString("device_key"),"fcm")
        state.put("phase2_pid",Process.myPid()).put("phase2_complete",true)
        check(session.writeTextAndSync(state.toString()))
        network.assertHealthy()
    }


    /** C5: a distinct old same-token owner already has an accepted held provider attempt.
     * The actual repository re-registers this client's durable identity and wins the route,
     * then production filtered Pull/inbound persistence/ACK consumes the transferred delivery.
     * The host keeps and later releases the original frozen provider response. */
    @Test fun phase3CoalescedOwnerPersistsAndReceivesTransferredDelivery() = runBlocking {
        state=JSONObject(session.readText())
        assertTrue(state.getBoolean("phase2_complete"))
        val oldOwner=args.getString("c5OldOwner") ?: error("c5OldOwner required")
        val capture=JSONObject(String(android.util.Base64.decode(args.getString("c5MergeCaptureBase64") ?: error("c5MergeCaptureBase64 required"),android.util.Base64.DEFAULT),Charsets.UTF_8))
        val delivery=capture.getString("delivery_id")
        val expectedBody="c5-coalesced-owner-"+"x".repeat(7000)
        assertTrue(isWakeup(capture))
        assertEquals(oldOwner,capture.getString("provider_device_key"))
        assertEquals(state.getString("device_key"),settings.getDeviceKey())
        val canonicalBefore=count("messages")
        val currentOwner=channels.syncProviderDeviceToken(providerToken)
        assertNotEquals("real route upsert must replace the distinct old owner",oldOwner,currentOwner)
        assertEquals(currentOwner,settings.getDeviceKey())
        val reopened=SettingsRepository(db.appSettingsDao(),AndroidKeystoreSecretStore(context,"c3_keystore_preferences"),
            context.getSharedPreferences("c3_settings_cache",Context.MODE_PRIVATE))
        assertEquals("new real settings/Keystore owner must read persisted current capability",currentOwner,reopened.getDeviceKey())
        val denied=request(network.baseUrl,"POST","/v2/messages/pull",JSONObject().put("device_key",oldOwner).put("delivery_id",delivery))
        assertEquals(0,denied.getJSONObject("data").getJSONArray("items").length())
        val deniedAck=request(args.getString("c3GatewayUrl") ?: error("c3GatewayUrl required"),"POST","/v2/messages/ack",JSONObject().put("device_key",oldOwner).put("delivery_ids",org.json.JSONArray().put(delivery)))
        assertEquals(0,deniedAck.getJSONObject("data").getInt("removed_count"))
        val transferred=channels.pullMessages(delivery)
        assertEquals(currentOwner,transferred.destination?.deviceKey)
        assertEquals(listOf(delivery),transferred.items.map { it.deliveryId })
        assertEquals(expectedBody,transferred.items.single().payload["body"])
        process(capture)
        assertFalse(drain().hasFailures)
        assertBody(expectedBody)
        assertEquals(canonicalBefore+1,count("messages"))
        assertEquals("acked",ackState(delivery))
        assertEquals(0,count("inbound_delivery_ack_outbox"))
        val scopedOwner=db.openHelper.readableDatabase.query("SELECT device_key FROM inbound_delivery_ledger WHERE delivery_id=?",arrayOf(delivery)).use {
            assertTrue(it.moveToFirst());val owner=it.getString(0);assertFalse(it.moveToNext());owner
        }
        assertEquals(currentOwner,scopedOwner)
        process(capture)
        assertEquals("frozen original wakeup replay must not duplicate canonical data",canonicalBefore+1,count("messages"))
        File(context.filesDir,"c5-owner-coalescing.json").writeTextAndSync(JSONObject()
            .put("old_owner",oldOwner).put("current_owner",currentOwner).put("persisted_owner",reopened.getDeviceKey())
            .put("delivery_id",delivery).put("message_id",capture.getString("message_id"))
            .put("canonical_before",canonicalBefore).put("canonical_after",count("messages"))
            .put("ack_state",ackState(delivery)).put("outbox_count",count("inbound_delivery_ack_outbox"))
            .put("pid",Process.myPid()).put("old_pull_denied",true).put("old_ack_removed_count",0).toString())
        network.assertHealthy()
    }

    private suspend fun drain(): ProviderAckDrainResult {
        val result=ProviderAckDrainCoordinator.drainPendingAcks(ledger::loadFairPendingAcks,ledger::beginAckAttempt,channels::ackMessages,ledger::markAckRecordsAcked)
        ledger.deferFailedAcks(result.uncertainFailures,lastAttemptUncertain=true)
        ledger.deferFailedAcks(result.definitiveFailures,lastAttemptUncertain=false)
        return result
    }
    private suspend fun process(data: JSONObject) {
        val map=data.keys().asSequence().associateWith { data.get(it).toString() }
        InboundMessageProcessor(runtimeResolver=InboundProcessorRuntimeResolver {
            DefaultInboundProcessorRuntime(channels,messages,entities,ledger,settings)
        }).process(context,map,"c3-captured-provider")
    }
    private fun isWakeup(data: JSONObject) = data.optString("provider_wakeup")=="1" || data.optString("provider_mode")=="wakeup"
    private suspend fun sendAndCapture(label: String, body: String, hold: Boolean=false): JSONObject {
        val op="c3-android-$label-${System.nanoTime()}"
        if(hold) request(fixture,"POST","/__test/configure",JSONObject().put("provider","fcm").put("token",providerToken).put("op_id",op).put("hold",true).put("max_hold_seconds",60))
        val result=request(network.baseUrl,"POST","/message",JSONObject().put("channel_id",channelId)
            .put("password",channelCredential).put("op_id",op).put("title","c3-$label").put("body",body).put("ttl",System.currentTimeMillis()/1000+3600))
        assertTrue(result.getBoolean("success"))
        val deadline=System.nanoTime()+15_000_000_000L
        while (System.nanoTime()<deadline) {
            val rows=request(fixture,"GET","/__test/captures?token=$providerToken&op_id=$op&limit=100",null).getJSONArray("captures")
            if (rows.length()>0) return rows.getJSONObject(0).getJSONObject("data")
            delay(25)
        }
        error("no actual provider capture for $label")
    }
    private fun request(base: String,method: String,path: String,body: JSONObject?): JSONObject {
        val c=(URL(base+path).openConnection() as HttpURLConnection).apply {
            requestMethod=method; connectTimeout=5_000; readTimeout=10_000
            setRequestProperty("Content-Type","application/json")
            args.getString("c3GatewayAuth")?.takeIf { it.isNotBlank() }?.let { setRequestProperty("Authorization","Bearer $it") }
            if(body!=null) { doOutput=true; outputStream.use { it.write(body.toString().toByteArray()) } }
        }
        val code=c.responseCode; val text=(if(code>=400)c.errorStream else c.inputStream).bufferedReader().use { it.readText() }; c.disconnect()
        check(code in 200..299) { "candidate HTTP $method $path failed $code" }
        return JSONObject(text)
    }
    private fun count(table: String,where: String="1=1") = db.openHelper.readableDatabase.query("SELECT count(*) FROM $table WHERE $where").use { it.moveToFirst();it.getInt(0) }
    private fun ackState(id: String): String? = db.openHelper.readableDatabase.query("SELECT ack_state FROM inbound_delivery_ledger WHERE delivery_id=?",arrayOf(id)).use { if(it.moveToFirst())it.getString(0) else null }
    private fun assertBody(expected: String) {
        val found=db.openHelper.readableDatabase.query("SELECT body FROM messages WHERE body=?",arrayOf(expected)).use { it.moveToFirst() }
        assertTrue("canonical body missing (length=${expected.length})",found)
    }
    private fun File.writeTextAndSync(text: String): Boolean { outputStream().use { it.write(text.toByteArray());it.fd.sync() };return true }
    companion object { private const val DB_NAME="c3_candidate_ordinary.db" }
}
