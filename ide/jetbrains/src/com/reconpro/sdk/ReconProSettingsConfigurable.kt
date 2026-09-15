package com.reconpro.sdk

import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBTextField
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel

/**
 * Tools | ReconPro settings: python interpreter + CLI timeout.
 * Persisted per-project via [ReconProSettings].
 */
class ReconProSettingsConfigurable(private val project: Project) : com.intellij.openapi.options.Configurable {

    private val pythonField = JBTextField()
    private val timeoutField = JBTextField()

    override fun getDisplayName(): String = "ReconPro"

    override fun createComponent(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.add(JLabel("Python interpreter (runs '<python> -m reconpro.cli')"))
        panel.add(pythonField)
        panel.add(JLabel("CLI timeout (seconds)"))
        panel.add(timeoutField)
        reset()
        return panel
    }

    override fun isModified(): Boolean {
        val s = ReconProSettings.get(project)
        return pythonField.text != s.pythonPath || timeoutField.text != s.timeoutSec.toString()
    }

    override fun apply() {
        ReconProSettings.update(
            project,
            pythonField.text.ifBlank { "python3" },
            timeoutField.text.toLongOrNull() ?: 120L,
        )
    }

    override fun reset() {
        val s = ReconProSettings.get(project)
        pythonField.text = s.pythonPath
        timeoutField.text = s.timeoutSec.toString()
    }
}
