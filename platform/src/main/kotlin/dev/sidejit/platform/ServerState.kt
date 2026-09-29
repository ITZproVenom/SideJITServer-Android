package dev.sidejit.platform

/**
 * How far the stack has actually got.
 *
 * Every stage is reported separately and truthfully. A stage that is not
 * implemented says so rather than staying silent, because a screen that shows
 * nothing and a screen that shows a working tunnel look far too similar when
 * the only thing you can do is read it from across a room.
 */
enum class StageStatus {
    /** The code for this stage does not exist yet. */
    NOT_IMPLEMENTED,

    /** Implemented, not started. */
    IDLE,

    /** Working on it. */
    RUNNING,

    /** Up and usable. */
    READY,

    /** Tried and failed; see [Stage.detail]. */
    FAILED,
}

data class Stage(
    val name: String,
    val status: StageStatus,
    val detail: String = "",
)

data class ServerState(
    val wifi: Stage = Stage("Wi-Fi", StageStatus.IDLE),
    val addresses: List<String> = emptyList(),
    val mdns: Stage = Stage("mDNS advertisement", StageStatus.NOT_IMPLEMENTED),
    val api: Stage = Stage("Local HTTP API", StageStatus.NOT_IMPLEMENTED),
    val pairing: Stage = Stage("Wireless pairing", StageStatus.NOT_IMPLEMENTED),
    val device: Stage = Stage("Paired iOS device", StageStatus.NOT_IMPLEMENTED),
    val tunnel: Stage = Stage("CoreDevice tunnel", StageStatus.NOT_IMPLEMENTED),
    val developerServices: Stage = Stage("Developer services", StageStatus.NOT_IMPLEMENTED),
    val jit: Stage = Stage("JIT", StageStatus.NOT_IMPLEMENTED),
    val setupCode: String? = null,
) {
    val stages: List<Stage>
        get() = listOf(wifi, mdns, api, pairing, device, tunnel, developerServices, jit)
}
