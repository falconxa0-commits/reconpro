-- plugin/reconpro.lua — autoload entry: registers :ReconPro* user commands.
if vim.g.loaded_reconpro then
  return
end
vim.g.loaded_reconpro = 1

local commands = require("reconpro.commands")

vim.api.nvim_create_user_command("ReconProScan", function(opts)
  commands.scan({
    bang = opts.bang,
    dir = opts.args ~= "" and opts.args or nil,
  })
end, {
  bang = true,
  nargs = "?",
  complete = "dir",
  desc = "ReconPro: AST vulnerability scan of the buffer's directory",
})

vim.api.nvim_create_user_command("ReconProSecrets", function(opts)
  commands.secrets({
    bang = opts.bang,
    dir = opts.args ~= "" and opts.args or nil,
  })
end, {
  bang = true,
  nargs = "?",
  complete = "dir",
  desc = "ReconPro: secrets scan (--json) of the buffer's directory",
})

vim.api.nvim_create_user_command("ReconProDoctor", function()
  commands.doctor()
end, {
  desc = "ReconPro: machine health check (doctor --json)",
})

vim.api.nvim_create_user_command("ReconProVersion", function()
  commands.version()
end, {
  desc = "ReconPro: show CLI version",
})
