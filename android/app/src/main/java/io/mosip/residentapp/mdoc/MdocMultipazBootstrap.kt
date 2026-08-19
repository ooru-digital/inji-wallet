package io.mosip.residentapp.mdoc

import android.content.Context
import android.util.Log
import org.multipaz.context.initializeApplication

/**
 * Lazily initializes Multipaz's global [org.multipaz.context.applicationContext].
 *
 * **Do not** call this from [android.app.Application.onCreate] before the RN stack is needed:
 * some builds crashed on cold start when Multipaz was touched too early. Call from the proximity
 * presenter coroutine instead (first presentment), using [Context.getApplicationContext].
 */
object MdocMultipazBootstrap {
    private const val TAG = "MdocMultipazBootstrap"

    @JvmStatic
    fun initFrom(context: Context) {
        try {
            initializeApplication(context.applicationContext)
        } catch (e: Throwable) {
            Log.e(TAG, "initializeApplication failed", e)
        }
    }
}
