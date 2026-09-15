package com.reconpro.sdk

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Core runner for the reconpro CLI inside IntelliJ Platform IDEs.
 *
 * SECURITY CONTRACT (mirrors the VS Code extension):
 *  - the CLI is executed with [ProcessBuilder] and an ARGV **LIST** — never a
 *    shell string, never `Runtime.getRuntime().exec("... " + path + " ...")`;
 *  - the project path is passed as a dedicated list element, so paths with
 *    spaces / quotes / `$()` are inert data, not shell syntax.
 *
 * Stream routing of the real CLI (reconpro 11.1.0, verified):
 *  - human-readable output (banner, Rich tables) -> STDERR
 *  - machine-readable output (`--json`, `--version`) -> STDOUT
 *
 * SARIF flow: `reconpro dev <projectDir>` saves the "last scan", which
 * `reconpro export <file>.sarif` serialises to SARIF 2.1.0. `ast` and
 * `secrets` alone never enter the SARIF (upstream behaviour), hence the
 * scan action runs `dev` before `export`.
 *
 * HONEST BUILD NOTE: this file is *source-validated only* in the sandbox that
 * produced it — there is no IntelliJ IDEA, no Gradle and no Kotlin compiler
 * available there (see README.md, section "Compile-blocked"). The plugin
 * skeleton compiles once opened in IntelliJ IDEA 2024.1+ with the gradle-intellij-plugin.
 */
object ReconProRunner {

    data class Settings(
        val pythonPath: String = "python3",
        val timeoutSec: Long = 120L,
    )

    /** Annotation-model finding parsed from SARIF 2.1.0. */
    data class Finding(
        val ruleId: String?,
        val level: String,
        val message: String,
        val file: String?,
        val startLine: Int?,           // 1-based; null -> whole-file annotation
        val securitySeverity: Double?, // rules[].properties["security-severity"], 0..10
        val remediation: String?,
    )

    data class CliResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val timedOut: Boolean,
    )

    /** Build the argv list: [pythonPath, "-m", "reconpro.cli", ...args]. */
    fun buildCommand(settings: Settings, args: List<String>): List<String> =
        listOf(settings.pythonPath, "-m", "reconpro.cli") + args

    /**
     * Run the CLI. argv LIST via ProcessBuilder — no shell involved.
     * COLUMNS=200 makes the Rich tables render deterministic widths.
     */
    fun run(settings: Settings, args: List<String>, cwd: File): CliResult {
        val argv = buildCommand(settings, args)
        val process = ProcessBuilder(argv)
            .directory(cwd)
            .apply {
                environment()["PYTHONUNBUFFERED"] = "1"
                environment()["COLUMNS"] = "200"
            }
            // No redirectErrorStream: stdout is JSON, stderr is human output —
            // the CLI intentionally splits the two streams (verified upstream).
            .start()
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val tOut = Thread { process.inputStream.bufferedReader().forEachLine { stdout.appendLine(it) } }
        val tErr = Thread { process.errorStream.bufferedReader().forEachLine { stderr.appendLine(it) } }
        tOut.start(); tErr.start()
        val finished = process.waitFor(settings.timeoutSec, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            tOut.join(2000); tErr.join(2000)
            return CliResult(124, stdout.toString(), stderr.toString(), timedOut = true)
        }
        tOut.join(5000); tErr.join(5000)
        return CliResult(process.exitValue(), stdout.toString(), stderr.toString(), timedOut = false)
    }

    // ── SARIF parsing (subset of SARIF 2.1.0 that reconpro emits) ─────────

    private data class SarifRegion(
        @SerializedName("startLine") val startLine: Int? = null,
    )

    private data class SarifArtifactLocation(
        @SerializedName("uri") val uri: String? = null,
    )

    private data class SarifPhysicalLocation(
        @SerializedName("artifactLocation") val artifactLocation: SarifArtifactLocation? = null,
        @SerializedName("region") val region: SarifRegion? = null,
    )

    private data class SarifLocation(
        @SerializedName("physicalLocation") val physicalLocation: SarifPhysicalLocation? = null,
    )

    private data class SarifMessage(
        @SerializedName("text") val text: String? = null,
        @SerializedName("markdown") val markdown: String? = null,
    )

    private data class SarifResult(
        @SerializedName("ruleId") val ruleId: String? = null,
        @SerializedName("level") val level: String? = null,
        @SerializedName("message") val message: SarifMessage? = null,
        @SerializedName("locations") val locations: List<SarifLocation>? = null,
        @SerializedName("properties") val properties: Map<String, String>? = null,
    )

    private data class SarifDriver(
        @SerializedName("name") val name: String? = null,
        @SerializedName("rules") val rules: List<SarifRule>? = null,
    )

    private data class SarifRule(
        @SerializedName("id") val id: String? = null,
        @SerializedName("properties") val properties: Map<String, String>? = null,
    )

    private data class SarifRun(
        @SerializedName("tool") val tool: SarifTool? = null,
        @SerializedName("results") val results: List<SarifResult>? = null,
    )

    private data class SarifTool(
        @SerializedName("driver") val driver: SarifDriver? = null,
    )

    private data class SarifLog(
        @SerializedName("version") val version: String? = null,
        @SerializedName("runs") val runs: List<SarifRun>? = null,
    )

    /** Parse SARIF JSON into the annotation model. Unresolvable/machine-level locations keep file = null. */
    fun parseSarif(sarifJson: String): List<Finding> {
        val log = Gson().fromJson(sarifJson, SarifLog::class.java)
        if (log?.version != "2.1.0" || log.runs.isNullOrEmpty()) return emptyList()
        val securitySeverityByRule = log.runs.asSequence()
            .mapNotNull { it.tool?.driver?.rules }
            .flatten()
            .filterNotNull()
            .mapNotNull { rule ->
                rule.id?.let { id -> rule.properties?.get("security-severity")?.toDoubleOrNull()?.let { id to it } }
            }
            .toMap()
        return log.runs.asSequence()
            .mapNotNull { it.results }
            .flatten()
            .filterNotNull()
            .map { r ->
                val phys = r.locations?.firstOrNull()?.physicalLocation
                Finding(
                    ruleId = r.ruleId,
                    level = r.level ?: "warning",
                    message = r.message?.text ?: r.message?.markdown ?: r.ruleId ?: "ReconPro finding",
                    file = phys?.artifactLocation?.uri,
                    startLine = phys?.region?.startLine,
                    securitySeverity = r.ruleId?.let { securitySeverityByRule[it] },
                    remediation = r.properties?.get("remediation"),
                )
            }
            .toList()
    }

    /** Map SARIF level + security-severity onto IntelliJ highlight severities. */
    fun toIntellijSeverity(f: Finding): com.intellij.lang.annotation.HighlightSeverity =
        when {
            f.level.equals("error", ignoreCase = true) -> com.intellij.lang.annotation.HighlightSeverity.ERROR
            (f.securitySeverity ?: 0.0) >= 7.0 -> com.intellij.lang.annotation.HighlightSeverity.ERROR
            f.level.equals("note", ignoreCase = true) -> com.intellij.lang.annotation.HighlightSeverity.INFORMATION
            else -> com.intellij.lang.annotation.HighlightSeverity.WARNING
        }

    /** The exact scan flow used by ReconProScanAction (also exercised by our CI validator). */
    fun scanProject(settings: Settings, projectDir: File): Pair<List<Finding>, CliResult> {
        val dev = run(settings, listOf("dev", projectDir.absolutePath), projectDir)
        if (dev.exitCode != 0) return emptyList<Finding>() to dev
        val sarifFile = File.createTempFile("reconpro-", ".sarif", projectDir)
        val exp = run(settings, listOf("export", sarifFile.absolutePath), projectDir)
        val findings = if (exp.exitCode == 0 && sarifFile.isFile) {
            parseSarif(sarifFile.readText()).filter { it.file != null }
        } else {
            emptyList()
        }
        sarifFile.delete()
        return findings to exp
    }
}
