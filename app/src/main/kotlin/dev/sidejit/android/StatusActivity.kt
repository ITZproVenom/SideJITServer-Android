package dev.sidejit.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.sidejit.core.logging.Log
import dev.sidejit.platform.ServerRuntime
import dev.sidejit.platform.ServerState
import dev.sidejit.platform.Stage
import dev.sidejit.platform.StageStatus

/**
 * Read-only status.
 *
 * There is deliberately nothing to press. Everything the server does, it does
 * because it was started, so this screen cannot be a prerequisite for any of
 * it and does not need a single focusable control to work with a D-pad.
 */
class StatusActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val runtime = ServerRuntime.get(this)
        ServerService.start(this)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(background = Ink, surface = Ink)) {
                Surface(modifier = Modifier.fillMaxSize(), color = Ink) {
                    val state by runtime.state.collectAsState()
                    StatusScreen(state)
                }
            }
        }
    }
}

private val Ink = Color(0xFF0B0B0F)
private val Muted = Color(0xFF9A9AA8)

@Composable
private fun StatusScreen(state: ServerState) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 28.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Text(
                text = "SideJIT Server",
                color = Color.White,
                fontSize = 30.sp,
                fontWeight = FontWeight.SemiBold,
            )
        }
        item {
            Text(
                text = if (state.addresses.isEmpty()) {
                    "No network address yet"
                } else {
                    state.addresses.joinToString("  ")
                },
                color = Muted,
                fontSize = 15.sp,
                fontFamily = FontFamily.Monospace,
            )
        }
        state.setupCode?.let { code ->
            item { SetupCode(code) }
        }
        item { Spacer(Modifier.width(1.dp)) }
        items(state.stages) { stage -> StageRow(stage) }
        item {
            Text(
                text = "Log",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.padding(top = 18.dp, bottom = 4.dp),
            )
        }
        items(Log.recent(80).reversed()) { line ->
            Text(
                text = line.toString(),
                color = Muted,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

@Composable
private fun SetupCode(code: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(Color(0xFF15151D))
            .padding(18.dp)
    ) {
        Text("Enter this code on your iPhone or iPad", color = Muted, fontSize = 14.sp)
        Text(
            text = code,
            color = Color.White,
            fontSize = 44.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
private fun StageRow(stage: Stage) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Spacer(
            Modifier
                .size(10.dp)
                .clip(CircleShape)
                .background(stage.status.colour())
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.fillMaxWidth()) {
            Text(stage.name, color = Color.White, fontSize = 16.sp)
            Text(
                text = stage.detail.ifBlank { stage.status.describe() },
                color = Muted,
                fontSize = 13.sp,
            )
        }
    }
}

private fun StageStatus.colour(): Color = when (this) {
    StageStatus.NOT_IMPLEMENTED -> Color(0xFF3A3A46)
    StageStatus.IDLE -> Color(0xFF6E6E80)
    StageStatus.RUNNING -> Color(0xFFE0A419)
    StageStatus.READY -> Color(0xFF34C759)
    StageStatus.FAILED -> Color(0xFFFF453A)
}

private fun StageStatus.describe(): String = when (this) {
    StageStatus.NOT_IMPLEMENTED -> "Not implemented yet"
    StageStatus.IDLE -> "Idle"
    StageStatus.RUNNING -> "Working"
    StageStatus.READY -> "Ready"
    StageStatus.FAILED -> "Failed"
}
