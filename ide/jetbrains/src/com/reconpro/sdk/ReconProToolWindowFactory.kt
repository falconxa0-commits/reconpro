package com.reconpro.sdk

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBTextArea
import javax.swing.JScrollPane
import javax.swing.SwingUtilities

/**
 * Bottom tool window "ReconPro" — a plain append-only console of the raw CLI
 * streams (the honest fallback surface whenever SARIF is unavailable or a
 * finding has no file-resolvable location).
 */
class ReconProToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val area = JBTextArea().apply {
            isEditable = false
            lineWrap = true
        }
        val panel = JScrollPane(area)
        val content = toolWindow.contentManager.factory.createContent(panel, "Output", true)
        toolWindow.contentManager.addContent(content)
        consoles[project.name] = area
    }

    companion object {
        private val consoles = mutableMapOf<String, JBTextArea>()

        fun append(project: Project, text: String) {
            SwingUtilities.invokeLater {
                consoles[project.name]?.apply {
                    append(text.trimEnd() + System.lineSeparator())
                    caretPosition = document.length
                }
            }
        }
    }
}

internal object ReconProToolWindow {
    fun append(project: Project, text: String) = ReconProToolWindowFactory.append(project, text)
}
