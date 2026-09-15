# reconpro.nvim — ReconPro security scanner for Neovim

Runs the [ReconPro](../..) CLI (`python -m reconpro.cli`) from Neovim:
AST vulnerability scans, secrets detection and machine health checks, with
results in the **quickfix list**. The CLI is always spawned via
`vim.fn.jobstart` with an **argv list — never a shell string** (no
`os.execute`, no `vim.fn.system`).

> **STATUS — honest:** this sandbox has **no `nvim` binary** (only vim 9.1,
> which lacks `jobstart`/`vim.api`), so the plugin is *structurally validated
> only*: `python3 tools/validate.py` checks the Lua sources for the
> jobstart/no-shell/setqflist contract and the vimdoc tags, and **executes
> the exact argv lists the Lua builds** against the real CLI (including a
> Python port of the Lua table-row parser to prove it extracts findings from
> live `ast` output). Loading the plugin in an actual Neovim is left to a
> machine that has one.

## Commands

| Command | Runs | Result |
|---|---|---|
| `:ReconProScan[!] [dir]` | `ast <buffer-dir>` | Rich table rows → quickfix (`!` also dumps raw output to a scratch window) |
| `:ReconProSecrets[!] [dir]` | `secrets <dir> --json` | JSON findings → quickfix |
| `:ReconProDoctor` | `doctor --json` | findings → quickfix + score/grade notification |
| `:ReconProVersion` | `--version` | notification |

## Install (lazy.nvim)

```lua
{
  dir = "~/src/reconpro/ide/neovim", -- or fork it into your config
  cmd = { "ReconProScan", "ReconProSecrets", "ReconProDoctor", "ReconProVersion" },
  config = function()
    require("reconpro").setup({
      python = "/home/you/.venv/bin/python3", -- interpreter that can import reconpro
      timeout = 60,                            -- seconds per CLI job
    })
  end,
}
```

Any plugin manager that puts `lua/`, `plugin/`, `doc/`, `syntax/` on the
runtimepath works. Run `:helptags ALL` to index `doc/reconpro.txt`.

## Files

```
lua/reconpro/init.lua       config, build_cmd (argv list), jobstart runner,
                            Rich-table parser, JSON/JSONL decoder, qf builders
lua/reconpro/commands.lua   :ReconProScan / Secrets / Doctor / Version
plugin/reconpro.lua         nvim_create_user_command registration (4 commands)
doc/reconpro.txt            full vimdoc (:h reconpro) with tags
syntax/reconpro-report.vim  highlighting for reconpro:// scratch buffers
```

## Upstream CLI quirks (documented in `:h reconpro-quirks`)

1. Human output → **stderr**, `--json`/`--version` → **stdout**.
2. `ast <single-file>` is an upstream no-op → `:ReconProScan` targets the
   buffer's *directory*.
3. The ast table's "Line" column holds evidence text, not line numbers →
   quickfix entries pin `lnum` to 1.
4. The ast table truncates file paths to the last 30 characters.

## Validate in this repo

```bash
python3 ide/neovim/tools/validate.py   # exit 0 = PASS
```
