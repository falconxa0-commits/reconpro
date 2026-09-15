-- reconpro/init.lua — core runner for the ReconPro Neovim plugin.
--
-- Runs the reconpro CLI (`python -m reconpro.cli`) with vim.fn.jobstart using
-- an ARGV **LIST** — never a shell string (no os.execute, no vim.fn.system).
-- Results land in the quickfix list via vim.fn.setqflist, parsed from the
-- CLI's JSON (--json commands) or from its Rich findings table (ast).
--
-- Upstream CLI facts (reconpro 11.1.0, verified):
--   * human output (banner, Rich tables) -> STDERR
--   * machine output (--json, --version)  -> STDOUT
--   * `reconpro ast <single-file>` is an upstream no-op (it only analyzes
--     directories) -> :ReconProScan always targets the buffer's directory.
--   * COLUMNS=200 forces deterministic Rich table widths.
--
-- Status: source-validated in a sandbox without a nvim binary (see
-- tools/validate.py — it also executes the exact argv lists built below).

local M = {}

-- Default config; override via require("reconpro").setup({ python = "...", timeout = 60 })
M.config = {
  python = (vim.fn.exepath("python3") ~= "") and vim.fn.exepath("python3") or "python3",
  timeout = 120, -- seconds; jobs are jobstop()ed after this
}

function M.setup(opts)
  opts = opts or {}
  for k, v in pairs(opts) do
    M.config[k] = v
  end
  return M
end

--- Build the argv LIST: { python, "-m", "reconpro.cli", ...args }.
--- The CLI is NEVER invoked through a shell string.
function M.build_cmd(args)
  return vim.list_extend({ M.config.python, "-m", "reconpro.cli" }, args or {})
end

--- Severity word -> quickfix "type" letter (E/W/I) and human label.
function M.severity_info(word)
  local w = string.upper(word or "")
  if w == "CRITICAL" or w == "HIGH" then
    return "E", w
  elseif w == "MEDIUM" then
    return "W", w
  end
  return "I", (w ~= "" and w or "INFO")
end

--- Parse a Rich table row of the form
---   │ CRITICAL │ /path/file.py │ pickle │ Unsafe Deserialization │
--- (the CLI's `ast` output) into { severity, file, code, message }.
--- Columns are split on the literal box character — Lua patterns cannot
--- express multibyte character classes, so vim.split(plain) is used instead.
function M.parse_table_row(line)
  if not line or not string.find(line, "│", 1, true) then
    return nil
  end
  local cols = vim.split(line, "│", { plain = true, trimempty = true })
  if #cols < 4 then
    return nil
  end
  local severity = vim.trim(cols[1])
  if not string.find(severity, "^[A-Z]+$") then
    return nil -- header/continuation/border rows
  end
  if not (severity == "CRITICAL" or severity == "HIGH" or severity == "MEDIUM" or severity == "LOW" or severity == "INFO") then
    return nil
  end
  local file = vim.trim(cols[2])
  local code = vim.trim(cols[3])
  local message = vim.trim(cols[4])
  if file == "" or message == "" then
    return nil
  end
  return { severity = severity, file = file, code = code, message = message }
end

--- Turn table rows into quickfix entries.
function M.rows_to_qflist(rows)
  local qf = {}
  for _, row in ipairs(rows or {}) do
    local qtype = M.severity_info(row.severity)
    table.insert(qf, {
      filename = row.file,
      lnum = 1, -- upstream ast table has no line numbers (see :h reconpro-quirks)
      col = 1,
      type = qtype,
      text = string.format("[%s] %s", row.severity, row.message),
    })
  end
  return qf
end

--- Decode JSON from accumulated stdout: tries the whole buffer first, then
--- per-line (JSON Lines) so future CLI versions emitting JSONL also work.
--- Returns decoded data or nil.
function M.json_decode_buffer(lines)
  local joined = table.concat(lines or {}, "\n")
  if vim.trim(joined) == "" then
    return nil
  end
  local ok, data = pcall(vim.fn.json_decode, joined)
  if ok and data ~= vim.NIL then
    return data
  end
  local decoded_lines = {}
  for _, line in ipairs(lines or {}) do
    local trimmed = vim.trim(line)
    if string.sub(trimmed, 1, 1) == "{" or string.sub(trimmed, 1, 1) == "[" then
      local ok2, obj = pcall(vim.fn.json_decode, trimmed)
      if ok2 and obj ~= vim.NIL then
        table.insert(decoded_lines, obj)
      end
    end
  end
  if #decoded_lines > 0 then
    return decoded_lines
  end
  return nil
end

--- Finding dicts (secrets --json / doctor --json) -> quickfix entries.
--- `asset` is the scanned root; per-file names appear in `title`
--- ("Hardcoded password in evil.py") — extracted when resolvable in `root`.
function M.findings_to_qflist(findings, root)
  local qf = {}
  for _, f in ipairs(findings or {}) do
    if type(f) == "table" then
      local qtype = M.severity_info(f.severity)
      local title = f.title or "reconpro finding"
      local fname = nil
      if root then
        -- title often ends with the basename of the affected file
        local base = string.match(title, "([%w_%-%.]+)%s*$")
        if base and string.find(base, "%.") then
          local candidate = root .. "/" .. base
          if vim.fn.filereadable(candidate) == 1 then
            fname = candidate
          end
        end
      end
      local entry = {
        type = qtype,
        lnum = 1,
        text = string.format("[%s] %s", string.upper(f.severity or "INFO"), title),
      }
      if fname then
        entry.filename = fname
      else
        entry.filename = f.asset or root or "reconpro"
      end
      if f.evidence and f.evidence ~= "" then
        entry.text = entry.text .. " (" .. tostring(f.evidence) .. ")"
      end
      table.insert(qf, entry)
    end
  end
  return qf
end

--- Run the CLI. `opts`: { cwd = string, on_exit = function(result) } where
--- result = { code, stdout = {lines}, stderr = {lines}, timed_out }.
--- Returns the job id. The argv list guarantees no shell interpretation.
function M.run(args, opts)
  opts = opts or {}
  local cmd = M.build_cmd(args)
  local result = { code = -1, stdout = {}, stderr = {}, timed_out = false, cmd = cmd }
  local timer = nil -- declared before the callbacks so they capture this upvalue
  local job_id = vim.fn.jobstart(cmd, {
    cwd = opts.cwd,
    stdout_buffered = true,
    stderr_buffered = true,
    env = {
      COLUMNS = "200",
      PYTHONUNBUFFERED = "1",
    },
    on_stdout = function(_, data)
      for _, line in ipairs(data or {}) do
        if line ~= "" then
          table.insert(result.stdout, line)
        end
      end
    end,
    on_stderr = function(_, data)
      for _, line in ipairs(data or {}) do
        if line ~= "" then
          table.insert(result.stderr, line)
        end
      end
    end,
    on_exit = function(_, code)
      if timer then
        timer:close()
      end
      result.code = code
      if opts.on_exit then
        opts.on_exit(result)
      end
    end,
  })
  if job_id <= 0 then
    vim.notify("reconpro: jobstart failed to launch " .. table.concat(cmd, " "), vim.log.levels.ERROR)
    return job_id
  end
  local timer = vim.loop.new_timer()
  timer:start(M.config.timeout * 1000, 0, vim.schedule_wrap(function()
    result.timed_out = true
    vim.fn.jobstop(job_id)
  end))
  return job_id
end

--- Console fallback: raw CLI streams in a scratch window with the
--- reconpro-report filetype (syntax/reconpro-report.vim highlights it).
function M.show_output(lines, title)
  local buf = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines or {})
  vim.api.nvim_buf_set_option(buf, "filetype", "reconpro-report")
  vim.api.nvim_buf_set_name(buf, title or "reconpro://output")
  vim.api.nvim_open_win(buf, true, { split = "below", win = 0, height = 12 })
end

return M
