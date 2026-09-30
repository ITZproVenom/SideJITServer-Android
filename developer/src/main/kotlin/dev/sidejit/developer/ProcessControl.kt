package dev.sidejit.developer

import dev.sidejit.core.serialization.JsonValue
import dev.sidejit.core.serialization.NsKeyedArchive
import dev.sidejit.core.serialization.jsonObject

object ProcessControl {
    const val SERVICE = "com.apple.instruments.server.services.processcontrol"
    const val DEBUGSERVER = "com.apple.internal.dt.coredevice.device.control.debugserver"
    const val DEBUGPROXY = "com.apple.debugserver"
    private const val SELECTOR_LAUNCH =
        "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:"

    fun launchSuspended(bundleId: String): JsonValue =
        jsonObject(
            "method" to JsonValue.of(SELECTOR_LAUNCH),
            "bundleIdentifier" to JsonValue.of(bundleId),
            "arguments" to JsonValue.of("[]"),
            "environment" to JsonValue.of("{}"),
            "options" to jsonObject(
                "StartSuspendedKey" to JsonValue.of(true),
                "KillExisting" to JsonValue.of(true),
            ),
        )

    fun resume(pid: Long): JsonValue =
        jsonObject("method" to JsonValue.of("startObservingPid:"), "pid" to JsonValue.of(pid))

    fun launchSuspendedArchive(bundleId: String): ByteArray {
        val options = NsKeyedArchive.dict(
            "StartSuspendedKey" to NsKeyedArchive.bool(true),
            "KillExisting" to NsKeyedArchive.bool(true),
        )
        return NsKeyedArchive.methodInvocation(
            selector = SELECTOR_LAUNCH,
            namedArgs = mapOf(
                "devicePath" to NsKeyedArchive.text(""),
                "bundleIdentifier" to NsKeyedArchive.text(bundleId),
                "environment" to NsKeyedArchive.dict(),
                "arguments" to NsKeyedArchive.array(),
                "options" to options,
            ),
        )
    }
}
