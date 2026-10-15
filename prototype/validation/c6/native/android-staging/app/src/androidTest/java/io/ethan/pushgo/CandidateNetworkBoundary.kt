package io.ethan.pushgo

import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.ServerSocket
import java.net.URL
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Controlled network boundary. Product request/response data is forwarded to the real
 * candidate unchanged; selected socket loss models unavailable/unknown network outcomes.
 * It never manufactures successful Gateway responses. */
internal class CandidateNetworkBoundary(
    private val upstream: String,
    port: Int,
    private val trace: File,
    private val beforeAck: (JSONObject) -> Unit,
) : AutoCloseable {
    private val listener = ServerSocket(port)
    val baseUrl = "http://127.0.0.1:${listener.localPort}"
    val requests = CopyOnWriteArrayList<String>()
    private val failure = AtomicReference<Throwable?>()
    val dropAckMode = AtomicReference<String?>(null) // before or after forwarding, held until caller clears (includes HTTP internal retries)
    val holdResponsePath = AtomicReference<String?>(null)
    private var held = CountDownLatch(1)
    private var released = CountDownLatch(1)
    fun prepareResponseHold(path: String) { held=CountDownLatch(1);released=CountDownLatch(1);holdResponsePath.set(path) }
    fun awaitHeld() { check(held.await(10,TimeUnit.SECONDS)) { "candidate response never held" } }
    fun releaseHeld() { released.countDown() }
    private val workers = CopyOnWriteArrayList<Thread>()
    private val acceptor = thread(name = "c3-candidate-network", isDaemon = true) {
        while (!listener.isClosed) {
            try {
                val socket = listener.accept()
                workers += thread(name = "c3-forward", isDaemon = true) {
                    socket.use { connection ->
                        try {
                            connection.soTimeout = 10_000
                            val reader = connection.getInputStream().bufferedReader()
                            val line = reader.readLine().split(' ')
                            val method = line[0]; val path = line[1]
                            val headers = linkedMapOf<String,String>()
                            while (true) {
                                val header = reader.readLine() ?: break
                                if (header.isEmpty()) break
                                headers[header.substringBefore(':')] = header.substringAfter(':').trim()
                            }
                            val size = headers.entries.firstOrNull { it.key.equals("Content-Length",true) }?.value?.toInt() ?: 0
                            val body = CharArray(size)
                            var read = 0
                            while (read < size) { val n = reader.read(body, read, size-read); check(n >= 0); read += n }
                            val raw = String(body)
                            requests += path
                            val ack = path.endsWith("/v2/messages/ack") || path.endsWith("/messages/ack")
                            if (ack) beforeAck(JSONObject(raw))
                            val loss = if (ack) dropAckMode.get() else null
                            record(path, "received", loss)
                            if (loss == "before") return@use
                            val actual = (URL(upstream.trimEnd('/') + path).openConnection() as HttpURLConnection).apply {
                                requestMethod = method; connectTimeout=5_000; readTimeout=15_000
                                headers.forEach { (key,value) -> if (!key.equals("Host",true) && !key.equals("Content-Length",true) && !key.equals("Connection",true)) setRequestProperty(key,value) }
                                setRequestProperty("Connection","close")
                                if (size > 0) { doOutput=true; outputStream.use { it.write(raw.toByteArray()) } }
                            }
                            val status = actual.responseCode
                            val bytes = (if (status >= 400) actual.errorStream else actual.inputStream)?.use { it.readBytes() } ?: byteArrayOf()
                            actual.disconnect()
                            record(path, "candidate_response", loss, status, if(ack) JSONObject(String(bytes)).optJSONObject("data") else null)
                            val plannedHold=holdResponsePath.get()
                            if(plannedHold==path && holdResponsePath.compareAndSet(plannedHold,null)) {
                                held.countDown(); check(released.await(10,TimeUnit.SECONDS)) { "held candidate response not released" }
                            }
                            if (loss == "after") return@use
                            connection.getOutputStream().apply {
                                write("HTTP/1.1 $status Forwarded\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray())
                                write(bytes); flush()
                            }
                        } catch (error: Throwable) { failure.compareAndSet(null,error) }
                    }
                }
            } catch (error: Throwable) { if (!listener.isClosed) failure.compareAndSet(null,error) }
        }
    }
    @Synchronized private fun record(path: String, stage: String, loss: String?, status: Int? = null, receipt: JSONObject? = null) {
        trace.appendText(JSONObject().put("path",path).put("stage",stage).put("fault",loss)
            .put("candidate_status",status).put("ack_receipt",receipt).put("pid",android.os.Process.myPid()).put("at_ns",System.nanoTime()).toString()+"\n")
    }
    fun assertHealthy() { failure.get()?.let { throw AssertionError("candidate network boundary failed",it) } }
    override fun close() { releaseHeld(); listener.close(); acceptor.join(1_000); workers.forEach { it.join(1_000) }; assertHealthy() }
}
