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
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collect
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Actual PrivateChannelClient/JNI/TLS/Room/AndroidKeystore. Host coordination
 * submits to the real candidate, owns fresh-DB ACK-failure triggers and restarts,
 * and cuts an opaque TLS relay. It never manufactures Gateway protocol success.
 * Host force-stops the isolated package before coherent main+WAL exports.
 */
@RunWith(AndroidJUnit4::class)
class CandidatePrivateC6DeviceTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val args get() = InstrumentationRegistry.getArguments()
    private val base get() = requireNotNull(args.getString("c6GatewayUrl")).trimEnd('/')
    private val controlUrl get() = requireNotNull(args.getString("c6ControlUrl")).trimEnd('/')
    private val auth get() = args.getString("c6GatewayToken")?.takeIf { it.isNotBlank() }
    private val session get() = File(context.filesDir,"c6-private-session.json")
    private lateinit var db: PushGoDatabase
    private lateinit var settings: SettingsRepository
    private lateinit var store: ChannelSubscriptionStore
    private lateinit var messages: MessageRepository
    private lateinit var entities: EntityRepository
    private lateinit var ledger: InboundDeliveryLedgerRepository
    private lateinit var channels: ChannelSubscriptionRepository
    private lateinit var client: PrivateChannelClient
    private lateinit var coordinator: TransportSwitchCoordinator
    private var phase="open"

    @Before fun open() {
        WarpLinkNativeBridge.installTestRuntime(null)
        assertTrue("source-bound real JNI must load",WarpLinkNativeBridge.isAvailable())
        assertEquals(2,WarpLinkNativeBridge.abiVersion())
        db=PushGoDatabase.buildForTest(context,"c6_private.db")
        val protectedStore=AndroidKeystoreSecretStore(context,"c6_private_keystore")
        settings=SettingsRepository(db.appSettingsDao(),protectedStore,
            context.getSharedPreferences("c6_private_settings",Context.MODE_PRIVATE))
        store=ChannelSubscriptionStore(db.channelSubscriptionDao(),protectedStore)
        messages=MessageRepository(db,db.messageDao(),db.messageChannelStatsDao(),db.messageMetadataIndexDao(),
            db.inboundDeliveryLedgerDao(),db.operationLedgerDao(),db.thingHeadDao(),db.thingSubMessageDao(),db.pendingThingMessageDao())
        entities=EntityRepository(db,db.inboundDeliveryLedgerDao(),db.operationLedgerDao(),db.eventChangeLogDao(),
            db.thingChangeLogDao(),db.thingSubEventDao(),db.topLevelEventHeadDao(),db.thingHeadDao(),db.thingSubMessageDao())
        ledger=InboundDeliveryLedgerRepository(db,db.inboundDeliveryLedgerDao(),db.inboundDeliveryAckOutboxDao(),db.legacyProviderIngressDao())
        val gate=CoordinatorTransportRouteWriterGate({coordinator}) { if(settings.getUseFcmChannel()) "fcm" else "private" }
        channels=ChannelSubscriptionRepository(store,settings,MessageStateCoordinator(context,messages),messages,entities,db,
            object:PushTokenProvider { override suspend fun fetchToken(timeoutMs:Long)=args.getString("c6MergeProviderToken") },
            awaitRouteSynchronization={coordinator.synchronize()},transportRouteWriterGate=gate,onRemoteRoute={coordinator.observeRoute(it)})
        client=PrivateChannelClient(context,channels,ledger,messages,entities,settings,
            awaitRouteSynchronization={coordinator.synchronize()},transportRouteWriterGate=gate,onRemoteRoute={coordinator.observeRoute(it)})
        coordinator=TransportSwitchCoordinator(client,object:TransportSelectionApplier {
            override suspend fun apply(useFcm:Boolean,providerToken:String?) {
                settings.setFcmToken(providerToken.takeIf { useFcm });settings.setUseFcmChannel(useFcm)
                client.setRuntime(useFcm,providerToken.takeIf { useFcm })
            }
            override suspend fun currentUseFcm()=settings.getUseFcmChannel()
            override suspend fun providerToken()=settings.getFcmToken()
        },currentGatewayUrl={channels.loadGatewayConfig().first},currentDeviceKey={settings.getDeviceKey()})
    }
    @After fun close() = runBlocking { if(::client.isInitialized) stopLoop();if(::db.isInitialized) db.close() }

    @Test fun phase1RealPrivatePersistsBeforeRejectedServerAck() = runBlocking {
        phase="phase1";check(!session.exists());assertEquals(0,count("messages"))
        settings.setServerAddress(base);settings.setGatewayToken(auth);settings.setUseFcmChannel(false)
        coordinator.synchronize();val key=requireNotNull(settings.getDeviceKey())
        val credential=UUID.randomUUID().toString()
        val channel=client.privateCreateChannel("C6 native Private ordinary",credential)
        assertTrue(channel.subscribed)
        store.upsertSubscription(base,channel.channelId,"C6 native Private ordinary",credential,System.currentTimeMillis())
        assertEquals(credential,ChannelSubscriptionStore(db.channelSubscriptionDao(),
            AndroidKeystoreSecretStore(context,"c6_private_keystore")).passwordFor(base,channel.channelId))
        startLoop();checkpoint("connected",JSONObject().put("device_key",key))
        await("real native TCP transport selected") { client.readTransportStatus().transport=="tcp" }
        val positive=submit("positive",channel.channelId,credential,"C6 actual native Private","c6-positive-exact-body")
        awaitCanonical(positive,key);checkpoint("ack-committed",positive)
        await("local ACKED after actual server commit") { ackState(positive.getString("delivery_id"),key)=="acked" }
        // Host installs a native-engine fresh-DB trigger rejecting the actual targets
        // ACK update. Expected Gateway exit70 is an independent real process receipt.
        checkpoint("arm-server-ack-storage-failure",JSONObject().put("device_key",key))
        val uncertain=submit("ack-storage-failure",channel.channelId,credential,
            "C6 Room survives server ACK commit failure","c6-server-ack-storage-failure-exact-body")
        awaitCanonical(uncertain,key);checkpoint("server-ack-storage-failed",uncertain)
        assertEquals(2,count("messages"))
        val state=ackState(uncertain.getString("delivery_id"),key);assertTrue(state in setOf("pending","acked"))
        write(session,JSONObject().put("phase1_pid",Process.myPid()).put("gateway",base).put("device_key",key)
            .put("channel_id",channel.channelId).put("password",credential).put("positive",positive).put("uncertain",uncertain)
            .put("uncertain_local_ack_state",state).put("canonical_count",2).put("phase1_complete",true))
        receipt("phase1",JSONObject().put("device_key",key).put("canonical_count",2).put("ledger_state",state)
            .put("scope","actual Room durability and real server DB ACK failure; pure wire-lost ACK NOT RUN"))
    }

    @Test fun phase2NewProcessReplaysReconnectsUnsubscribesAndPreparesTransfer() = runBlocking {
        phase="phase2";val prior=JSONObject(session.readText());assertTrue(prior.getBoolean("phase1_complete"))
        assertNotEquals(prior.getInt("phase1_pid"),Process.myPid())
        val key=prior.getString("device_key");val uncertain=prior.getJSONObject("uncertain")
        // Storage assertions precede every network call/session start in this PID.
        assertEquals(base,settings.getServerAddress());assertEquals(key,settings.getDeviceKey())
        assertEquals(key,SettingsRepository(db.appSettingsDao(),AndroidKeystoreSecretStore(context,"c6_private_keystore"),
            context.getSharedPreferences("c6_private_settings",Context.MODE_PRIVATE)).getDeviceKey())
        assertCanonical(uncertain,key)
        assertEquals(prior.getString("uncertain_local_ack_state"),ackState(uncertain.getString("delivery_id"),key))
        assertEquals(prior.getInt("canonical_count"),count("messages"))
        startLoop();checkpoint("replay-ack-committed",uncertain)
        await("replayed local ledger ACKED") { ackState(uncertain.getString("delivery_id"),key)=="acked" }
        assertEquals(prior.getInt("canonical_count"),count("messages"))
        checkpoint("cut-owned-tcp-relay",JSONObject().put("device_key",key))
        checkpoint("reconnected",JSONObject().put("device_key",key))
        val reconnected=submit("after-reconnect",prior.getString("channel_id"),prior.getString("password"),
            "C6 actual reconnect","c6-reconnect-exact-body")
        awaitCanonical(reconnected,key);checkpoint("ack-committed",reconnected);assertEquals(3,count("messages"))
        client.privateUnsubscribeChannel(prior.getString("channel_id"));store.softDeleteSubscription(base,prior.getString("channel_id"))
        assertTrue(channels.loadSubscriptions().isEmpty())
        val excluded=submit("after-unsubscribe",prior.getString("channel_id"),prior.getString("password"),
            "C6 future fanout excluded","c6-no-private-target-after-unsubscribe")
        checkpoint("no-private-target",excluded);assertEquals(3,count("messages"))
        val transferCredential=UUID.randomUUID().toString()
        val transferChannel=client.privateCreateChannel("C6 retained Private transfer",transferCredential)
        store.upsertSubscription(base,transferChannel.channelId,"C6 retained Private transfer",transferCredential,System.currentTimeMillis())
        // Stop the real old session before acceptance; no DELIVER-hold API needed.
        stopLoop();checkpoint("old-private-offline",JSONObject().put("device_key",key))
        val transferred=submit("owner-transfer",transferChannel.channelId,transferCredential,
            "C6 retained old Private owner","c6-owner-transfer-exact-body")
        assertEquals(0,canonicalCount(transferred.getString("message_id")))
        val mergeCapability=requireNotNull(args.getString("c6MergeProviderToken"))
        coordinator.switchToFcm(mergeCapability);assertTrue(settings.getUseFcmChannel())
        checkpoint("old-route-exited-to-fcm",JSONObject().put("device_key",key).put("delivery",transferred))
        val transfer=JSONObject().put("old_owner",key).put("channel_id",transferChannel.channelId)
            .put("password",transferCredential).put("delivery",transferred).put("merge_provider_token",mergeCapability)
        write(File(context.filesDir,"c6-owner-transfer.json"),transfer)
        prior.put("phase2_pid",Process.myPid()).put("phase2_complete",true).put("canonical_count",3)
        write(session,prior);receipt("phase2",JSONObject().put("device_key",key).put("canonical_count",3)
            .put("replay_ack_state",ackState(uncertain.getString("delivery_id"),key)).put("transfer",transfer))
    }

    @Test fun phase3FreshRealOwnerCoalescesAndConsumesRetainedPrivateDelivery() = runBlocking {
        phase="phase3";check(!session.exists());assertEquals(0,count("messages"))
        val transfer=JSONObject(String(android.util.Base64.decode(requireNotNull(args.getString("c6OwnerTransferBase64")),
            android.util.Base64.DEFAULT),Charsets.UTF_8))
        val oldOwner=transfer.getString("old_owner");val expected=transfer.getJSONObject("delivery")
        val mergeCapability=transfer.getString("merge_provider_token")
        settings.setServerAddress(base);settings.setGatewayToken(auth);settings.setUseFcmChannel(true);settings.setFcmToken(mergeCapability)
        val owner=channels.syncProviderDeviceToken(mergeCapability)
        assertNotEquals(oldOwner,owner);assertEquals(owner,settings.getDeviceKey())
        val reopened=SettingsRepository(db.appSettingsDao(),AndroidKeystoreSecretStore(context,"c6_private_keystore"),
            context.getSharedPreferences("c6_private_settings",Context.MODE_PRIVATE))
        assertEquals(owner,reopened.getDeviceKey())
        checkpoint("owner-coalesced",JSONObject().put("old_owner",oldOwner).put("current_owner",owner).put("delivery",expected))
        store.upsertSubscription(base,transfer.getString("channel_id"),"C6 retained Private transfer",transfer.getString("password"),System.currentTimeMillis())
        coordinator.switchToPrivate();assertFalse(settings.getUseFcmChannel())
        startLoop();awaitCanonical(expected,owner);checkpoint("transferred-private-ack-committed",expected)
        await("current owner ledger ACKED") { ackState(expected.getString("delivery_id"),owner)=="acked" };assertEquals(1,count("messages"))
        coordinator.switchToFcm(mergeCapability);assertTrue(settings.getUseFcmChannel())
        checkpoint("winner-private-route-exited",JSONObject().put("device_key",owner).put("delivery",expected));assertEquals(1,count("messages"))
        receipt("phase3",JSONObject().put("old_owner",oldOwner).put("current_owner",owner).put("persisted_owner",reopened.getDeviceKey())
            .put("delivery",expected).put("canonical_count",1).put("ledger_state",ackState(expected.getString("delivery_id"),owner)))
    }

    @Test fun tlsRejectsWrongCaHostOrLeafPinBeforePrivateDelivery() = runBlocking {
        phase="tls-negative";assertEquals(0,count("messages"))
        val kind=requireNotNull(args.getString("c6TlsFailureKind"));assertTrue(kind in setOf("wrong_ca","wrong_host","wrong_pin"))
        settings.setServerAddress(base);settings.setGatewayToken(auth);settings.setUseFcmChannel(false)
        val transitions=java.util.Collections.synchronizedList(mutableListOf<PrivateChannelClient.TransportStatus>())
        val observed=java.util.concurrent.atomic.AtomicReference<String?>(null)
        // Observe the existing production flow synchronously before real session start.
        // A Fatal TLS detail is immediately followed by Reconnecting/backoff; polling
        // only the latest state can miss it. No fake runtime or native event injection.
        val watcher=launch(Dispatchers.Unconfined,start=CoroutineStart.UNDISPATCHED) {
            client.transportStatusFlow.collect { status ->
                if(transitions.size<128) transitions.add(status)
                val detail=status.detail.orEmpty();val value=detail.lowercase()
                val matches=when(kind) {
                    "wrong_ca" -> value.contains("unknownissuer") || value.contains("unknown issuer")
                    "wrong_host" -> value.contains("notvalidforname") || value.contains("not valid for name") || value.contains("name mismatch")
                    else -> value.contains("certificate pin mismatch")
                }
                if(matches) observed.compareAndSet(null,detail)
            }
        }
        try {
            startLoop()
            await("actual native TLS rejection") { observed.get()!=null }
            val detail=requireNotNull(observed.get())
            checkpoint("tls-rejected",JSONObject().put("kind",kind).put("native_detail",detail))
            assertEquals(0,count("messages"));assertEquals(0,count("inbound_delivery_ledger"))
            receipt("tls-$kind",JSONObject().put("kind",kind).put("native_detail",detail).put("canonical_count",0))
        } finally {
            watcher.cancelAndJoin()
            val snapshot=synchronized(transitions) { transitions.toList() }
            val sequence=org.json.JSONArray()
            snapshot.forEach { status -> sequence.put(JSONObject().put("stage",status.stage).put("transport",status.transport)
                .put("detail",status.detail).put("updated_at_ms",status.updatedAtMs)) }
            receipt("tls-observer-$kind",JSONObject().put("kind",kind).put("transitions",sequence)
                .put("specific_native_detail_observed",observed.get()!=null).put("deadline_ms",20_000))
        }
    }
    private fun startLoop() { client.setRuntime(false,null);client.setForeground(true) }
    private suspend fun stopLoop() {
        client.setForeground(false);client.setRuntime(true,null)
        // Teardown bookkeeping only, never a product outcome or injected event.
        val field=PrivateChannelClient::class.java.getDeclaredField("scope");field.isAccessible=true
        val ownedScope=field.get(client) as CoroutineScope
        await("owned client cleanup jobs finish") { ownedScope.coroutineContext[Job]?.children?.none { it.isActive } != false }
    }
    private suspend fun await(label:String,check:suspend ()->Boolean) {
        withTimeout(20_000) { while(!check()) delay(25) }
    }
    private suspend fun awaitCanonical(expected:JSONObject,owner:String) {
        await("exact canonical ${expected.getString("delivery_id")}") { canonicalCount(expected.getString("message_id"))==1 };assertCanonical(expected,owner)
    }
    private fun assertCanonical(expected:JSONObject,owner:String) {
        db.openHelper.readableDatabase.query("SELECT title,body FROM messages WHERE message_id=?",arrayOf(expected.getString("message_id"))).use {
            assertTrue(it.moveToFirst());assertEquals(expected.getString("title"),it.getString(0));assertEquals(expected.getString("body"),it.getString(1));assertFalse(it.moveToNext())
        }
        assertTrue(ackState(expected.getString("delivery_id"),owner) in setOf("pending","acked"))
    }
    private fun canonicalCount(id:String)=db.openHelper.readableDatabase.query("SELECT count(*) FROM messages WHERE message_id=?",arrayOf(id)).use { it.moveToFirst();it.getInt(0) }
    private fun count(table:String)=db.openHelper.readableDatabase.query("SELECT count(*) FROM $table").use { it.moveToFirst();it.getInt(0) }
    private fun ackState(id:String,owner:String):String?=db.openHelper.readableDatabase.query(
        "SELECT ack_state FROM inbound_delivery_ledger WHERE gateway_url=? AND device_key=? AND delivery_id=?",arrayOf(base,owner,id)
    ).use { if(it.moveToFirst())it.getString(0) else null }
    private fun submit(label:String,channel:String,credential:String,title:String,body:String)=checkpoint("submit",JSONObject()
        .put("label",label).put("channel_id",channel).put("password",credential).put("title",title).put("body",body))
    private fun checkpoint(action:String,data:JSONObject):JSONObject {
        val request=JSONObject().put("action",action).put("phase",phase).put("pid",Process.myPid()).put("data",data)
        val connection=(URL("$controlUrl/checkpoint").openConnection() as HttpURLConnection).apply {
            requestMethod="POST";connectTimeout=5_000;readTimeout=20_000;doOutput=true;setRequestProperty("Content-Type","application/json")
        }
        return try {
            connection.outputStream.use { it.write(request.toString().toByteArray()) }
            val status=connection.responseCode;val raw=(if(status>=400)connection.errorStream else connection.inputStream).bufferedReader().use { it.readText() }
            assertEquals("host coordination failed: $raw",200,status)
            JSONObject(raw).also { assertTrue("facts were not verified",it.getBoolean("verified")) }.getJSONObject("data")
        } finally { connection.disconnect() }
    }
    private fun receipt(name:String,value:JSONObject) { write(File(context.filesDir,"c6-$name.json"),value.put("pid",Process.myPid())) }
    private fun write(file:File,value:JSONObject) { file.outputStream().use { it.write(value.toString().toByteArray());it.fd.sync() } }
}
