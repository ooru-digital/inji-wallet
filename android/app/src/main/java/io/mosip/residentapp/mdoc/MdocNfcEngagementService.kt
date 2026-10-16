package io.mosip.residentapp.mdoc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import io.mosip.residentapp.MainActivity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.nfc.MdocNfcEngagementHelper
import org.multipaz.nfc.CommandApdu
import org.multipaz.nfc.Nfc
import org.multipaz.nfc.ResponseApdu
import org.multipaz.util.UUID

/**
 * Answers an ISO 18013-5 reader tapped against this phone (NFC engagement).
 *
 * Only the handshake happens here, and only for as long as the phones touch: we hand the reader
 * our device engagement in an NFC static handover and tell it to find us over BLE. The holder then
 * picks which card to share in the app, and the session runs over BLE exactly as after the reader
 * scans our QR code - see [MdocNfcEngagements] and [InjiIso18013ProximityPresenter.start].
 *
 * Modelled on Multipaz's `MdocNdefService`, without its Compose presentment UI.
 */
class MdocNfcEngagementService : HostApduService() {

    private sealed class Event {
        class Apdu(val command: CommandApdu) : Event()
        class Deactivated(val reason: Int) : Event()
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val events = Channel<Event>(Channel.UNLIMITED)
    private var loop: Job? = null

    private var engagement: MdocNfcEngagementHelper? = null
    private var firstCommand: CommandApdu? = null
    private var apdusReceived = 0

    @Volatile
    private var handshakeDone = false

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate")
        // Responses go back through sendResponseApdu() from this one coroutine, so the suspending
        // NFC helper never runs on the binder thread the OS calls us on.
        loop = scope.launch {
            for (event in events) {
                try {
                    when (event) {
                        is Event.Apdu -> process(event.command)?.let { sendResponseApdu(it.encode()) }
                        is Event.Deactivated -> reset(event.reason)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.w(TAG, "Error handling NFC event", e)
                }
            }
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy")
        scope.cancel()
        super.onDestroy()
    }

    override fun processCommandApdu(encoded: ByteArray, extras: Bundle?): ByteArray? {
        val command = try {
            CommandApdu.decode(encoded)
        } catch (e: Exception) {
            // Extended APDUs can arrive partial; a deactivation usually follows.
            Log.w(TAG, "Couldn't decode APDU", e)
            return null
        }
        // Every command goes to the helper until the phones separate - including those after the
        // handover is ready, because the reader still has to read it out (READ BINARY).
        events.trySend(Event.Apdu(command))
        return null
    }

    override fun onDeactivated(reason: Int) {
        Log.i(TAG, "onDeactivated: reason=$reason")
        // The tap is over, so the activity can come forward without disturbing it.
        if (handshakeDone) bringAppForward()
        // Unblocks the helper if it is waiting on a response the reader will never collect. Called
        // directly rather than through [events], as the event loop may be waiting inside the helper.
        engagement?.let { helper -> scope.launch { helper.processDeactivated(reason) } }
        events.trySend(Event.Deactivated(reason))
    }

    private suspend fun process(command: CommandApdu): ResponseApdu? {
        // Recent Android wants an instant answer to SELECT, or it may route the tap to the wallet
        // role holder instead. Answer it first, then replay it to the helper once that exists.
        if (apdusReceived == 0) {
            apdusReceived = 1
            firstCommand = command
            return ResponseApdu(status = Nfc.RESPONSE_STATUS_SUCCESS)
        }
        val helper = engagement ?: startHandshake().also { engagement = it }
        if (apdusReceived++ == 1) {
            helper.processApdu(firstCommand!!)
        }
        return helper.processApdu(command)
    }

    private suspend fun startHandshake(): MdocNfcEngagementHelper {
        MdocMultipazBootstrap.initFrom(applicationContext)
        val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
        // The same BLE mode as the QR flow: we advertise, the reader connects. A fresh UUID per tap
        // so one session's advertisement can't be picked up by the next.
        val ble = MdocConnectionMethodBle(
            supportsPeripheralServerMode = true,
            supportsCentralClientMode = false,
            peripheralServerModeUuid = UUID.randomUUID(),
            centralClientModeUuid = null,
        )
        Log.i(TAG, "Handshake started; offering $ble")
        return MdocNfcEngagementHelper(
            eDeviceKey = eDeviceKey.publicKey,
            onHandoverComplete = { methods, encodedDeviceEngagement, handover ->
                handshakeDone = true
                MdocNfcEngagements.publish(eDeviceKey, encodedDeviceEngagement, handover, methods)
                // The app comes forward in onDeactivated, once the reader has read the handover:
                // starting the activity while the phones still touch would rebind this service.
            },
            onError = { error ->
                // Often not a wallet reader at all - a payment terminal, or another phone reading
                // tags. Nothing for the holder to see.
                Log.w(TAG, "Handshake failed; probably not an mdoc reader", error)
            },
            staticHandoverMethods = listOf(ble),
        )
    }

    private fun bringAppForward() {
        val intent = Intent(applicationContext, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
            putExtra(EXTRA_NFC_TAP, true)
        }
        try {
            applicationContext.startActivity(intent)
        } catch (e: Exception) {
            Log.w(TAG, "Couldn't bring the wallet forward", e)
        }
    }

    private fun reset(reason: Int) {
        // Android may reuse this service instance for the next tap.
        Log.i(TAG, "Reset after deactivation (reason=$reason, handshakeDone=$handshakeDone)")
        engagement = null
        firstCommand = null
        apdusReceived = 0
        handshakeDone = false
    }

    companion object {
        private const val TAG = "MdocNfcEngagement"
        const val EXTRA_NFC_TAP = "io.ooru.credissuerwallet.NFC_TAP"
    }
}
