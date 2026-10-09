package io.mosip.residentapp.mdoc

import android.util.Log
import kotlinx.io.bytestring.ByteString
import org.multipaz.cbor.DataItem
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethod
import java.util.UUID

/**
 * A reader that has tapped this phone and is now waiting for us over BLE.
 *
 * Produced by [MdocNfcEngagementService] when the NFC handshake completes, consumed by
 * [InjiIso18013ProximityPresenter] once the holder has picked which card to share. Everything the
 * QR flow takes from the card's persisted engagement comes from here instead: the engagement the
 * reader received, its ephemeral key, the BLE method it will look for, and the NFC handover that
 * binds the tap into the session transcript.
 */
class MdocNfcEngagement(
    val id: String,
    val eDeviceKey: EcPrivateKey,
    val encodedDeviceEngagement: ByteString,
    val handover: DataItem,
    val connectionMethods: List<MdocConnectionMethod>,
    val receivedAtMillis: Long,
)

/**
 * The tap waiting to be answered, if any.
 *
 * Only ever one: a second tap replaces the first, because the reader behind the first has gone.
 * It also goes stale on its own - the reader gives up on BLE if nothing connects, so a pick made
 * after that would only advertise to nobody.
 */
object MdocNfcEngagements {
    private const val TAG = "MdocNfcEngagements"

    /** Readers typically wait about 30 s for the BLE connection; leave room to start advertising. */
    private const val MAX_AGE_MILLIS = 25_000L

    fun interface Listener {
        fun onEngaged(engagement: MdocNfcEngagement)
    }

    @Volatile
    private var pending: MdocNfcEngagement? = null

    @Volatile
    var listener: Listener? = null

    fun publish(
        eDeviceKey: EcPrivateKey,
        encodedDeviceEngagement: ByteString,
        handover: DataItem,
        connectionMethods: List<MdocConnectionMethod>,
    ): MdocNfcEngagement {
        val engagement = MdocNfcEngagement(
            id = UUID.randomUUID().toString(),
            eDeviceKey = eDeviceKey,
            encodedDeviceEngagement = encodedDeviceEngagement,
            handover = handover,
            connectionMethods = connectionMethods,
            receivedAtMillis = System.currentTimeMillis(),
        )
        pending = engagement
        Log.i(TAG, "Tap ready as ${engagement.id}; methods=$connectionMethods")
        listener?.onEngaged(engagement) ?: Log.i(TAG, "No listener yet; JS will ask on start")
        return engagement
    }

    /** The pending tap if it is still fresh, without consuming it. */
    fun peek(): MdocNfcEngagement? =
        pending?.takeIf { System.currentTimeMillis() - it.receivedAtMillis < MAX_AGE_MILLIS }

    /** Hands the tap [id] over to a session. Null if it was replaced, expired or already taken. */
    fun take(id: String): MdocNfcEngagement? = synchronized(this) {
        val engagement = peek()?.takeIf { it.id == id }
        if (engagement != null) pending = null
        engagement
    }

    /** The holder backed out of the picker: forget the tap, the reader will time out. */
    fun discard(id: String) = synchronized(this) {
        if (pending?.id == id) pending = null
    }
}
