package io.mosip.residentapp.mdoc

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import io.mosip.residentapp.R

/**
 * Keeps ISO 18013-5 proximity BLE advertising + GATT alive when the user leaves Inji (e.g. opens
 * Tap2iD on the same device). Without a foreground service, Android often suspends the app and the
 * verifier never completes GATT / state-characteristic handshake.
 */
class MdocProximityPresentmentForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (_: Exception) {
        }
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                ensureChannel()
                val notification = buildNotification()
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        startForeground(
                            NOTIFICATION_ID,
                            notification,
                            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
                        )
                    } else {
                        startForeground(NOTIFICATION_ID, notification)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "startForeground failed", e)
                    stopSelf()
                    return START_NOT_STICKY
                }
            }
            ACTION_STOP -> {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                    } else {
                        @Suppress("DEPRECATION")
                        stopForeground(true)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "stopForeground in ACTION_STOP", e)
                }
                stopSelf()
            }
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun buildNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(getString(R.string.mdoc_proximity_notif_title))
                .setContentText(getString(R.string.mdoc_proximity_notif_text))
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setCategory(Notification.CATEGORY_SERVICE)
                .setPriority(Notification.PRIORITY_LOW)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(getString(R.string.mdoc_proximity_notif_title))
                .setContentText(getString(R.string.mdoc_proximity_notif_text))
                .setOngoing(true)
                .setPriority(Notification.PRIORITY_LOW)
                .build()
        }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val nm = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.mdoc_proximity_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    companion object {
        private const val TAG = "MdocProximityFgSvc"
        private const val CHANNEL_ID = "mdoc_iso18013_proximity"
        private const val NOTIFICATION_ID = 0x6d646f63 // "mdoc"

        const val ACTION_START = "io.mosip.residentapp.mdoc.PROXIMITY_FG_START"
        const val ACTION_STOP = "io.mosip.residentapp.mdoc.PROXIMITY_FG_STOP"

        fun start(context: Context) {
            val app = context.applicationContext
            val startRunnable = Runnable {
                val intent = Intent(app, MdocProximityPresentmentForegroundService::class.java)
                    .setAction(ACTION_START)
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        app.startForegroundService(intent)
                    } else {
                        @Suppress("DEPRECATION")
                        app.startService(intent)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start foreground service", e)
                }
            }
            // startForegroundService + Service.onStartCommand are safest when sequenced on the main
            // looper (OEM race with BLE thread / concurrent stop).
            if (Looper.myLooper() == Looper.getMainLooper()) {
                startRunnable.run()
            } else {
                Handler(Looper.getMainLooper()).post(startRunnable)
            }
        }

        fun stop(context: Context) {
            val app = context.applicationContext
            try {
                app.stopService(Intent(app, MdocProximityPresentmentForegroundService::class.java))
            } catch (e: Exception) {
                Log.w(TAG, "stopService failed (may not be running)", e)
            }
        }
    }
}
