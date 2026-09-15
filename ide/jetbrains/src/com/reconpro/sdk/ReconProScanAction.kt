package com.reconpro.sdk

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.ui.Messages

/**
 * Tools | ReconPro | Scan Project (AST + Secrets).
 *
 * Runs on a background thread (read action NOT needed — the CLI runs outside
 * the IDE), then annotates files from the SARIF produced by
 * [ReconProRunner.scanProject]. `ast`/`secrets` console output is appended to
 * the ReconPro tool window as the fallback surface when SARIF is unavailable.
 *
 * COMPILE-BLOCKED NOTE: like the rest of this skeleton, this file is source-
 * validated only in the producing sandbox (no IntelliJ SDK/Gradle there).
 */
class ReconProScanAction : AnAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.getData(CommonDataKeys.PROJECT) ?: return
        val projectDir = project.basePath?.let { java.io.File(it) } ?: run {
            Messages.showWarningDialog("Project has no directory on disk.", "ReconPro")
            return
        }
        val settings = ReconProSettings.get(project)
        ApplicationManager.getApplication().executeOnPooledThread {
            val ast = ReconProRunner.run(settings, listOf("ast", projectDir.absolutePath), projectDir)
            val secrets = ReconProRunner.run(settings, listOf("secrets", projectDir.absolutePath, "--json"), projectDir)
            val (findings, export) = ReconProRunner.scanProject(settings, projectDir)

            ApplicationManager.getApplication().invokeLater {
                ReconProToolWindow.append(
                    project,
                    """
                    ast exit=${ast.exitCode}
                    secrets exit=${secrets.exitCode}
                    export exit=${export.exitCode}
                    SARIF findings (file-resolvable): ${findings.size}
                    """.trimIndent() + "\n" + ast.stderr.trim(),
                )
                if (findings.isEmpty()) {
                    Messages.showInfoMessage(
                        "ReconPro scan finished — no file-resolvable SARIF findings.\nSee the ReconPro tool window for raw CLI output.",
                        "ReconPro",
                    )
                } else {
                    ReconProAnnotator.update(project, findings)
                    Messages.showInfoMessage("ReconPro scan finished — ${findings.size} finding(s) annotated.", "ReconPro")
                }
            }
        }
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible = e.getData(CommonDataKeys.PROJECT)?.basePath != null
    }
}
