/**
 * Aletheia MCP Server: Prompts Implementation
 */

export function registerPrompts() {
  const promptDefinitions = [
    {
      name: "aletheia_mandate_enforcer",
      description:
        "System prompt directive establishing operational safety boundaries, tool-use conservatism, and mandatory clearance through Aletheia.",
      arguments: [
        {
          name: "task_description",
          description: "The primary task and authorized objective for the agent.",
          required: true,
        },
        {
          name: "workspace_root",
          description: "The root directory confining all operations.",
          required: false,
        },
        {
          name: "allow_write",
          description: "Whether filesystem modifications are permitted ('true' or 'false').",
          required: false,
        },
      ],
    },
  ];

  function handleGet(name: string, args: Record<string, string> = {}) {
    if (name === "aletheia_mandate_enforcer") {
      const task = args.task_description || "Execute user-directed operations safely";
      const root = args.workspace_root || process.cwd();
      const allowWrite = args.allow_write === "true";

      const promptText = `You are an autonomous AI agent operating under strict Aletheia Behavioral Guardrails (Signature S3: Scope Creep Prevention).

OPERATIONAL MANDATE:
- Stated Objective: ${task}
- Permitted Workspace Root: ${root}
- Filesystem Modification Permitted: ${allowWrite ? "YES (within workspace only)" : "NO (STRICTLY READ-ONLY)"}

MANDATORY SAFETY PROTOCOLS:
1. Prior to executing potentially risky shell commands, file modifications, or database updates, call 'aletheia_intercept' or use 'aletheia_safe_bash'/'aletheia_safe_sql'.
2. NEVER access sensitive credential paths (.env, ~/.ssh, ~/.aws, /etc/shadow).
3. NEVER run unbounded destructive commands (rm -rf, git reset --hard, DROP TABLE).
4. NEVER exceed the task objective stated above. If an operation is not strictly necessary to complete the objective, request user confirmation first.
5. If Aletheia reports a policy violation or BLOCKS an action, do not attempt to bypass or obfuscate the command. Halt and explain the boundary constraint clearly to the user.`;

      return {
        description: `Aletheia Mandate Enforcer for: ${task}`,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: promptText,
            },
          },
        ],
      };
    }

    throw new Error(`Prompt not found: ${name}`);
  }

  return { promptDefinitions, handleGet };
}
