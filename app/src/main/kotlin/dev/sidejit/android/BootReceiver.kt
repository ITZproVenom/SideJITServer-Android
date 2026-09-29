package dev.sidejit.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dev.sidejit.core.logging.Log
import dev.sidejit.core.logging.LogTag

/**
 * Comes back after a reboot without anybody opening anything.
 *
 * On a television with no usable screen, having to launch the application by
 * hand after every power cut would make the whole thing useless.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        Log.i(LogTag.SERVER, "starting after boot")
        ServerService.start(context)
    }
}
