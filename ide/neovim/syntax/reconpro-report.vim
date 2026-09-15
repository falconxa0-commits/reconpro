" reconpro-report.vim — syntax for ReconPro raw CLI output buffers
" (reconpro://ast, reconpro://secrets, reconpro://doctor scratch windows).
if exists("b:current_syntax")
  finish
endif

" Severity words as printed by the CLI (Rich tables + plain lines)
syn match reconproCritical   "\<CRITICAL\>"
syn match reconproHigh       "\<HIGH\>"
syn match reconproMedium     "\<MEDIUM\>"
syn match reconproLow        "\<LOW\>"
syn match reconproInfo       "\<INFO\>"

" Rule ids like RP-HARDCODED_SECRETS
syn match reconproRuleId     "\<RP-[A-Z0-9_]\+\>"

" Banner noise + summary lines
syn match reconproSummary    "vulnerability pattern(s) found\|secret(s) found\|No findings\|No vulnerabilities found\|grade [A-F+]"
syn match reconproBanner     "E L E V E N   B L A D E S"
syn match reconproExit       "exit=\d\+"

hi def link reconproCritical  ErrorMsg
hi def link reconproHigh      WarningMsg
hi def link reconproMedium    Todo
hi def link reconproLow       Comment
hi def link reconproInfo      Comment
hi def link reconproRuleId    Identifier
hi def link reconproSummary   Statement
hi def link reconproBanner    Comment
hi def link reconproExit      Special

let b:current_syntax = "reconpro-report"
