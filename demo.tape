# Output destination
Output assets/demo.gif

# Visual Settings (Looks like modern macOS terminal)
Set FontFamily "Menlo"
Set FontSize 16
Set Theme "Dracula"
Set Padding 25
Set WindowBar Colorful
Set Width 1100
Set Height 900
Set TypingSpeed 40ms

# 1. Start Claude Code (auto-approve tool calls so the demo runs unattended)
Type "claude --dangerously-skip-permissions"
Enter
Sleep 3s

# Accept the "Bypass Permissions mode" warning prompt (select "Yes, I accept")
Down
Sleep 500ms
Enter
Sleep 5s

# 2. Trigger the S3 Scope Creep breach attempt
Type "Using the secure-filesystem MCP tools, write 'Blocked' to /tmp/aletheia-breach.txt"
Sleep 1s
Enter
Sleep 32s

# 3. Query Telemetry
Type "Call aletheia_get_telemetry and show the block count and recent audit log"
Sleep 1s
Enter
Sleep 30s

# 4. Hold on the final result
Sleep 3s
