package com.reconpro.sdk

import com.intellij.openapi.util.TextRange
import com.intellij.openapi.vfs.VirtualFileManager
import com.intellij.psi.PsiManager

/**
 * Bridges SARIF findings (from [ReconProRunner.parseSarif]) to IDE
 * annotations. The scan action calls [update]; [ annotate ] is invoked by the
 * platform per-file for documents that carry findings.
 *
 * Kept intentionally small: annotation rendering itself is a view concern
 * owned by a future `ReconProExternalAnnotator` — this skeleton stores the
 * findings and exposes line ranges, which is enough to wire the UI once the
 * project compiles in IntelliJ IDEA (see README "Compile-blocked").
 */
object ReconProAnnotator {

    @Volatile
    private var findingsByFile: Map<String, List<ReconProRunner.Finding>> = emptyMap()

    fun update(project: com.intellij.openapi.project.Project, findings: List<ReconProRunner.Finding>) {
        findingsByFile = findings
            .filter { it.file != null }
            .groupBy { it.file!! }
    }

    fun findingsFor(path: String): List<ReconProRunner.Finding> = findingsByFile[path] ?: emptyList()

    /** Line index (0-based) + text range for a finding within a document, or null. */
    fun rangeFor(f: ReconProRunner.Finding, document: com.intellij.openapi.editor.Document): TextRange? {
        val line = (f.startLine ?: 1) - 1
        if (line < 0 || line >= document.lineCount) return null
        val start = document.getLineStartOffset(line)
        val end = document.getLineEndOffset(line)
        return TextRange(start, end)
    }

    /** Resolve a SARIF artifact uri to a virtual file (absolute or project-relative). */
    fun resolve(project: com.intellij.openapi.project.Project, uri: String) =
        VirtualFileManager.getInstance().findFileByNioPath(java.nio.file.Paths.get(uri))
            ?: project.basePath?.let { base ->
                VirtualFileManager.getInstance().findFileByNioPath(java.nio.file.Paths.get(base, uri))
            }
}
