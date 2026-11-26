package com.cipher.p2p.transport

import android.content.Context
import android.hardware.usb.UsbManager
import com.hoho.android.usbserial.driver.UsbSerialPort
import com.hoho.android.usbserial.driver.UsbSerialProber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.zip.CRC32

/**
 * LoRa radio over USB-C (Android USB host). The radio is just a dumb pipe: it only ever
 * receives already-encrypted envelope fragments, so a compromised radio firmware learns
 * nothing except that traffic exists.
 *
 * Framing on the serial line:  0x94 0xC3 | len(2) | msgId(4) | idx(1) | total(1) | data | crc32(4)
 * (The 0x94C3 magic matches Meshtastic's stream header so the same boards work; for stock
 * Meshtastic firmware, wrap fragments in its protobuf ToRadio packets instead.)
 */
class LoraUsbTransport(private val context: Context) : Transport {
    override val kind = LinkKind.LORA
    private var port: UsbSerialPort? = null
    private val rx = Channel<ByteArray>(capacity = 64)
    private val partial = HashMap<Int, Array<ByteArray?>>()
    override val incoming: Flow<ByteArray> = rx.receiveAsFlow()

    fun open(): Boolean {
        val usb = context.getSystemService(Context.USB_SERVICE) as UsbManager
        val driver = UsbSerialProber.getDefaultProber().findAllDrivers(usb).firstOrNull() ?: return false
        if (!usb.hasPermission(driver.device)) return false           // UI requests permission first
        val conn = usb.openDevice(driver.device) ?: return false
        port = driver.ports[0].apply { open(conn); setParameters(115200, 8, UsbSerialPort.STOPBITS_1, UsbSerialPort.PARITY_NONE) }
        return true
    }

    override fun isAvailableFor(address: String) = port != null

    override suspend fun send(address: String, frame: ByteArray): Boolean = withContext(Dispatchers.IO) {
        val p = port ?: return@withContext false
        val chunks = frame.toList().chunked(FRAG).map { it.toByteArray() }
        if (chunks.size > 255) return@withContext false
        val id = java.security.SecureRandom().nextInt()
        chunks.forEachIndexed { i, c ->
            val body = ByteBuffer.allocate(6 + c.size).putInt(id).put(i.toByte()).put(chunks.size.toByte()).put(c).array()
            val crc = CRC32().apply { update(body) }.value.toInt()
            val out = ByteBuffer.allocate(4 + body.size + 4)
                .put(0x94.toByte()).put(0xC3.toByte()).putShort(body.size.toShort()).put(body).putInt(crc).array()
            p.write(out, 2000)
            Thread.sleep(AIRTIME_GAP_MS) // respect duty-cycle / airtime limits on 865–867 MHz
        }
        true
    }

    /** Feed raw serial bytes here from a SerialInputOutputManager listener. */
    fun onSerialFrame(body: ByteArray, crc: Int) {
        if (CRC32().apply { update(body) }.value.toInt() != crc || body.size < 7) return
        val bb = ByteBuffer.wrap(body)
        val id = bb.int; val idx = bb.get().toInt() and 0xff; val total = bb.get().toInt() and 0xff
        if (total == 0 || idx >= total) return
        val data = ByteArray(bb.remaining()).also { bb.get(it) }
        val slots = partial.getOrPut(id) { arrayOfNulls(total) }
        if (slots.size != total) return
        slots[idx] = data
        if (slots.all { it != null }) { partial.remove(id); rx.trySend(slots.fold(ByteArray(0)) { a, b -> a + b!! }) }
        if (partial.size > 32) partial.keys.first().let(partial::remove) // bound memory against floods
    }

    fun close() { runCatching { port?.close() }; port = null }

    companion object { private const val FRAG = 200; private const val AIRTIME_GAP_MS = 400L }
}
