package com.reconpro.sdk

import com.intellij.openapi.components.service
import com.intellij.openapi.project.Project

/**
 * Per-project ReconPro settings backing [ReconProSettingsConfigurable].
 * Defaults mirror the VS Code extension: python3 + 120s.
 */
class ReconProSettings(val pythonPath: String, val timeoutSec: Long) {

    companion object {
        fun get(project: Project): ReconProRunner.Settings {
            val state = project.service<State>()
            return ReconProRunner.Settings(
                pythonPath = state.pythonPath.ifBlank { "python3" },
                timeoutSec = if (state.timeoutSec > 0) state.timeoutSec else 120L,
            )
        }

        fun update(project: Project, pythonPath: String, timeoutSec: Long) {
            val state = project.service<State>()
            state.pythonPath = pythonPath
            state.timeoutSec = timeoutSec
        }
    }

    @com.intellij.openapi.components.State(
        name = "ReconProSettings",
        storages = [com.intellij.openapi.components.Storage("reconpro.xml")],
    )
    class State {
        var pythonPath: String = "python3"
        var timeoutSec: Long = 120L
    }
}
