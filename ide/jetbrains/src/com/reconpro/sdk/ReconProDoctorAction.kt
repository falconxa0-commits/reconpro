package com.reconpro.sdk

import com.google.gson.Gson
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.ui.Messages

/**
 * Tools | ReconPro | Doctor: Health Check — runs `reconpro doctor --json`
 * (JSON arrives on STDOUT; human output on STDERR — verified upstream) and
 * shows the findings/score/grade summary.
 */
class ReconProDoctorAction : AnAction() {

    private data class DoctorSummary(
        val target: String? = null,
        val total_findings: Int = 0,
        val total_score: Int = 0,
        val grade: String? = null,
    )

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.getData(CommonDataKeys.PROJECT) ?: return
        val cwd = project.basePath?.let { java.io.File(it) } ?: java.io.File(System.getProperty("java.io.tmpdir"))
        val settings = ReconProSettings.get(project)
        ApplicationManager.getApplication().executeOnPooledThread {
            val result = ReconProRunner.run(settings, listOf("doctor", "--json"), cwd)
            ApplicationManager.getApplication().invokeLater {
                if (result.exitCode != 0) {
                    ReconProToolWindow.append(project, result.stderr)
                    Messages.showErrorDialog("reconpro doctor failed (exit ${result.exitCode}). See ReconPro tool window.", "ReconPro")
                    return@invokeLater
                }
                val summary = runCatching { Gson().fromJson(result.stdout, DoctorSummary::class.java) }.getOrNull()
                if (summary == null) {
                    ReconProToolWindow.append(project, result.stdout)
                    Messages.showWarningDialog("doctor returned non-JSON output — see ReconPro tool window.", "ReconPro")
                    return@invokeLater
                }
                ReconProToolWindow.append(
                    project,
                    "doctor: target=${summary.target} findings=${summary.total_findings} score=${summary.total_score} grade=${summary.grade}",
                )
                Messages.showInfoMessage(
                    "ReconPro doctor: ${summary.total_findings} finding(s), score ${summary.total_score}/100, grade ${summary.grade}.",
                    "ReconPro",
                )
            }
        }
    }
}
