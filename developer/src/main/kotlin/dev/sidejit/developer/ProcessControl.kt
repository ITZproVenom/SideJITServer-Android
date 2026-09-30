package dev.sidejit.developer

import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.jsonObject

/**
 * DVT ProcessControl message shapes used to launch an app suspended for JIT.
 *
 * Real DVT uses NSKeyedArchive / RemoteXPC method calls. Until a live channel is
 * available these builders produce the logical request payloads higher layers will send.
 */
object ProcessControl {
    const val SERVICE = "com.apple.instruments.server.services.processcontrol"

    fun launchSuspended(bundleId: String): JsonValue =
        jsonObject(
            "method" to JsonValue.of("launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:"),
            "bundleIdentifier" to JsonValue.of(bundleId),
            "arguments" to JsonValue.of("[]"),
            "environment" to JsonValue.of("{}"),
            "options" to jsonObject(
                "StartSuspendedKey" to JsonValue.of(true),
                "KillExisting" to JsonValue.of(true),
            ),
        )

    fun resume(pid: Long): JsonValue =
        jsonObject(
            "method" to JsonValue.of("startObservingPid:"),
            "pid" to JsonValue.of(pid),
        )
}
