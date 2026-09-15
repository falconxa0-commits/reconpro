package com.reconpro.sdk;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Thin wrapper around the reconpro CLI, run as {@code <python> -m reconpro.cli ...}.
 * Every call uses a ProcessBuilder ARGUMENT LIST — never a shell string.
 *
 * <p>Config: constructor args or env RECONPRO_PYTHON (default
 * /home/z/.venv/bin/python3), RECONPRO_ROOT (subprocess cwd, default
 * /home/z/my-project/download/reconpro-github). Default timeout 120s.</p>
 *
 * <p>Verified CLI quirks (reconpro 11.1.0): {@code --version} and
 * {@code doctor --json} write to STDOUT; {@code history} has NO --json flag
 * (exit 2) and its human table goes to STDERR, so {@link #history()} returns
 * raw text. {@code export} takes one output path, format auto-detected from
 * the extension (.sarif/.md/.json/.html).</p>
 */
public final class ReconProClient {

    public static final String DEFAULT_PYTHON = "/home/z/.venv/bin/python3";
    public static final String DEFAULT_ROOT = "/home/z/my-project/download/reconpro-github";
    public static final long DEFAULT_TIMEOUT_SECONDS = 120;
    /** Formats accepted by the CLI `export` subcommand. */
    public static final List<String> EXPORT_FORMATS = Arrays.asList("sarif", "md", "json", "html");
    private static final String INVALID_TARGET_CHARS = ";$`&|<>(){}[]!*'\"\\\n\r\t ";

    /** Typed error carrying the CLI exit code and captured stderr. */
    public static final class SdkException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final int exitCode;
        public final String stderrText;

        public SdkException(String message, int exitCode, String stderrText) {
            super(message);
            this.exitCode = exitCode;
            this.stderrText = stderrText;
        }
    }

    /** Raw result of a successful CLI invocation. */
    public record Result(int exitCode, String stdout, String stderr) {}

    private final String pythonPath;
    private final String root;
    private final long timeoutSeconds;

    public ReconProClient() {
        this(envOrDefault("RECONPRO_PYTHON", DEFAULT_PYTHON),
             envOrDefault("RECONPRO_ROOT", DEFAULT_ROOT),
             DEFAULT_TIMEOUT_SECONDS);
    }

    public ReconProClient(String pythonPath, String root, long timeoutSeconds) {
        this.pythonPath = pythonPath;
        this.root = root;
        this.timeoutSeconds = timeoutSeconds;
    }

    private static String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    /** Python executable this client shells out to. */
    public String pythonPath() {
        return pythonPath;
    }

    /** Argument list handed to ProcessBuilder (unit-testable; no shell involved). */
    public List<String> buildCommand(List<String> cliArgs) {
        List<String> command = new ArrayList<>();
        command.add(pythonPath);
        command.add("-m");
        command.add("reconpro.cli");
        command.addAll(cliArgs);
        return command;
    }

    /** Runs the CLI; returns stdout/stderr on exit 0, throws {@link SdkException} otherwise. */
    public Result run(List<String> cliArgs) {
        List<String> command = buildCommand(cliArgs);
        ProcessBuilder pb = new ProcessBuilder(command); // argument list, never a shell string
        pb.directory(new File(root));
        pb.redirectInput(ProcessBuilder.Redirect.INHERIT);
        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            throw new SdkException("failed to start " + pythonPath + ": " + e.getMessage(), -1, "");
        }
        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        Thread outReader = drainAsync(process.getInputStream(), out);
        Thread errReader = drainAsync(process.getErrorStream(), err);
        outReader.start();
        errReader.start();
        boolean finished;
        try {
            finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new SdkException("interrupted while waiting for reconpro CLI", -1, err.toString());
        }
        if (!finished) {
            process.destroyForcibly();
            throw new SdkException("reconpro CLI timed out after " + timeoutSeconds + "s", -1, err.toString());
        }
        joinQuietly(outReader);
        joinQuietly(errReader);
        int code = process.exitValue();
        String stdout = out.toString();
        String stderr = err.toString();
        if (code != 0) {
            throw new SdkException("reconpro CLI exited with code " + code + ": "
                    + truncate(stderr, 400), code, stderr);
        }
        return new Result(code, stdout, stderr);
    }

    /** CLI version string, e.g. "ReconPro 11.1.0". */
    public String version() {
        return run(List.of("--version")).stdout().trim();
    }

    /** Local health check. Returns the raw JSON string (zero-dep SDK: no JSON parser). */
    public String doctor() {
        return run(List.of("doctor", "--json")).stdout();
    }

    /** Scan history as raw text (CLI quirk: history has no --json flag; table on STDERR). */
    public String history() {
        Result result = run(List.of("history"));
        return result.stderr().isBlank() ? result.stdout().trim() : result.stderr().trim();
    }

    /** Full remote scan of a domain/URL (hits the network). Returns raw JSON string. */
    public String scan(String target) {
        return run(List.of("scan", validateTarget(target), "--json")).stdout();
    }

    /**
     * Exports the last scan to {@code path} (CLI {@code export} subcommand, format from
     * extension). Returns the path written. Requires a previous scan in history.
     */
    public String export(String path, String format) {
        String fmt = format == null ? "" : format.trim().toLowerCase();
        if (!EXPORT_FORMATS.contains(fmt)) {
            throw new IllegalArgumentException(
                    "unsupported export format '" + format + "'; expected one of " + EXPORT_FORMATS);
        }
        String out = path == null ? "" : path.trim();
        if (out.isEmpty()) {
            throw new IllegalArgumentException("export path must be non-empty");
        }
        int slash = Math.max(out.lastIndexOf('/'), out.lastIndexOf('\\'));
        if (!out.substring(slash + 1).contains(".")) {
            out = out + "." + fmt;
        }
        run(List.of("export", out));
        return out;
    }

    /** Client-side target validation: rejects shell metacharacters before spawning. */
    public static String validateTarget(String target) {
        String text = target == null ? "" : target.trim();
        if (text.isEmpty()) {
            throw new IllegalArgumentException("target must be a non-empty string");
        }
        for (int i = 0; i < text.length(); i++) {
            if (INVALID_TARGET_CHARS.indexOf(text.charAt(i)) >= 0) {
                throw new IllegalArgumentException(
                        "target contains shell metacharacters: " + text);
            }
        }
        return text;
    }

    private static Thread drainAsync(java.io.InputStream stream, StringBuilder buffer) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    buffer.append(line).append('\n');
                }
            } catch (IOException ignored) {
                // stream closed / process killed — best effort drain
            }
        });
        thread.setDaemon(true);
        return thread;
    }

    private static void joinQuietly(Thread thread) {
        try {
            thread.join(5_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String truncate(String text, int max) {
        String flat = text == null ? "" : text.replace('\n', ' ');
        return flat.length() <= max ? flat : flat.substring(0, max) + "…";
    }
}
