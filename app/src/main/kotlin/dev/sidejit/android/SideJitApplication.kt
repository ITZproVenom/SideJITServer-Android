package dev.sidejit.android

import android.app.Application
import android.os.Build
import android.util.Log as AndroidLog
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogLevel
import dev.sidejit.core.logging.LogSink
import dev.sidejit.core.logging.LogTag

class SideJitApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Mirror the application log into logcat so a device attached to
        // nothing at all can still be read with `adb logcat` if one is ever
        // available. The lines are already redacted by this point.
        Log.addSink(
            LogSink { line ->
                val message = line.toString()
                when (line.level) {
                    LogLevel.DEBUG -> AndroidLog.d(TAG, message)
                    LogLevel.INFO -> AndroidLog.i(TAG, message)
                    LogLevel.WARN -> AndroidLog.w(TAG, message)
                    LogLevel.ERROR -> AndroidLog.e(TAG, message)
                }
            }
        )

        Log.i(
            LogTag.SERVER,
            "SideJIT Server starting on ${Build.MANUFACTURER} ${Build.MODEL}, " +
                "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
        )

        // The server must come up because the application was launched, not
        // because somebody managed to press a button on a broken screen.
        ServerService.start(this)
    }

    private companion object {
        const val TAG = "SideJIT"
    }
}
