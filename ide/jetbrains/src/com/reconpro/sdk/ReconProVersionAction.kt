package com.reconpro.sdk

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.ui.Messages

/** Tools | ReconPro | Show CLI Version — `reconpro --version` (STDOUT). */
class ReconProVersionAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.getData(CommonDataKeys.PROJECT)
        val settings = project?.let { ReconProSettings.get(it) } ?: ReconProRunner.Settings()
        val cwd = project?.basePath?.let { java.io.File(it) } ?: java.io.File(System.getProperty("java.io.tmpdir"))
        val result = ReconProRunner.run(settings, listOf("--version"), cwd)
        val version = result.stdout.ifBlank { result.stderr }.trim().ifBlank { "unknown" }
        Messages.showInfoMessage("ReconPro CLI: $version", "ReconPro")
    }
}
