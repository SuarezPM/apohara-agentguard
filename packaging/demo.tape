Output packaging/demo.gif

Set Shell bash
Set Width 900
Set Height 500
Set FontSize 18
Set Theme "Catppuccin Mocha"

# Seed PATH so the shell finds the release binary
Type `export PATH="$PWD/target/release:$PATH"`
Enter
Sleep 500ms

# 1 — cmdsubst evasion → Block
Type "apohara-agentguard check '$(echo rm) -rf ~'"
Enter
Sleep 900ms

# 2 — printf-hexesc piped to sh → Block
Type `apohara-agentguard check "printf '\x72\x6d\x20\x2d\x72\x66\x20\x7e' | sh"`
Enter
Sleep 900ms

# 3 — benign git commit → Allow
Type `apohara-agentguard check 'git commit -m "fix the rm -rf helper"'`
Enter
Sleep 600ms

# Closing one-liner
Type "# deterministic. offline. no LLM."
Enter
Sleep 1200ms
