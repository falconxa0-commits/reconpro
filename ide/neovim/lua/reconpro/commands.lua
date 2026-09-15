-- reconpro/commands.lua — user-command implementations.
--
-- :ReconProScan    — ast scan of the current buffer's DIRECTORY (upstream
--                    `ast <file>` is a no-op; see :h reconpro-quirks)
-- :ReconProSecrets — secrets scan (--json) of the buffer's directory
-- :ReconProDoctor  — machine health check (doctor --json)
-- :ReconProVersion — CLI version
--
-- All commands run the CLI through reconpro.run() (jobstart + argv list, no
-- shell) and push results into the quickfix list via vim.fn.setqflist;
-- the raw CLI output stays available via :ReconProScan! (console fallback).

local core = require("reconpro.init")

local M = {}

local function dir_of_buffer()
  local buf = vim.api.nvim_get_current_buf()
  local name = vim.api.nvim_buf_get_name(buf)
  if name == "" then
    return vim.fn.getcwd()
  end
  return vim.fn.fnamemodify(name, ":h")
end

local function qflist_open(entries, what)
  if #entries == 0 then
    vim.notify("reconpro: no findings (" .. what .. ").", vim.log.levels.INFO)
    return
  end
  vim.fn.setqflist({}, "r", { title = "ReconPro " .. what, items = entries })
  vim.cmd("cwindow")
  vim.notify(string.format("reconpro: %d finding(s) in quickfix (%s).", #entries, what), vim.log.levels.WARN)
end

--- :ReconProScan[!] [dir] — ast scan (Rich table output is parsed; with ! the
--- raw output is ALSO dumped to a scratch console window).
function M.scan(opts)
  opts = opts or {}
  local dir = opts.dir or dir_of_buffer()
  local console = opts.bang == true
  core.run({ "ast", dir }, {
    cwd = dir,
    on_exit = function(result)
      if console then
        core.show_output(result.stderr, "reconpro://ast")
      end
      if result.code ~= 0 then
        vim.notify(string.format("reconpro: ast exited %d", result.code), vim.log.levels.ERROR)
        core.show_output(result.stderr, "reconpro://ast")
        return
      end
      local rows = {}
      for _, line in ipairs(result.stderr) do -- human table arrives on STDERR
        local row = core.parse_table_row(line)
        if row then
          table.insert(rows, row)
        end
      end
      qflist_open(core.rows_to_qflist(rows), "ast")
    end,
  })
end

--- :ReconProSecrets[!] [dir] — secrets scan; JSON output on STDOUT.
function M.secrets(opts)
  opts = opts or {}
  local dir = opts.dir or dir_of_buffer()
  core.run({ "secrets", dir, "--json" }, {
    cwd = dir,
    on_exit = function(result)
      if opts.bang == true then
        core.show_output(result.stdout, "reconpro://secrets")
      end
      if result.code ~= 0 then
        vim.notify(string.format("reconpro: secrets exited %d", result.code), vim.log.levels.ERROR)
        return
      end
      local data = core.json_decode_buffer(result.stdout)
      qflist_open(core.findings_to_qflist(data, dir), "secrets")
    end,
  })
end

--- :ReconProDoctor — machine health check; findings to quickfix + summary.
function M.doctor()
  core.run({ "doctor", "--json" }, {
    cwd = vim.fn.getcwd(),
    on_exit = function(result)
      if result.code ~= 0 then
        vim.notify(string.format("reconpro: doctor exited %d", result.code), vim.log.levels.ERROR)
        return
      end
      local data = core.json_decode_buffer(result.stdout)
      if type(data) ~= "table" or data.total_findings == nil then
        vim.notify("reconpro: doctor returned non-JSON output", vim.log.levels.WARN)
        core.show_output(result.stdout, "reconpro://doctor")
        return
      end
      local findings = data.findings or data.module_results and data.module_results.doctor and data.module_results.doctor.findings or {}
      qflist_open(core.findings_to_qflist(findings, nil), "doctor")
      vim.notify(string.format(
        "reconpro doctor: %d finding(s), score %s/100, grade %s",
        tonumber(data.total_findings) or 0,
        tostring(data.total_score or "?"),
        tostring(data.grade or "?")
      ), vim.log.levels.INFO)
    end,
  })
end

--- :ReconProVersion — print CLI version.
function M.version()
  core.run({ "--version" }, {
    cwd = vim.fn.getcwd(),
    on_exit = function(result)
      local out = result.stdout or {}
      local version = (#out > 0) and out[1] or "unknown"
      vim.notify("reconpro CLI: " .. version, vim.log.levels.INFO)
    end,
  })
end

return M
