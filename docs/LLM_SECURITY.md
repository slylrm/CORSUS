# Optional LLM security testing

WeppenTest's standard scanner stays deterministic and AI-free. Garak, PyRIT and Promptfoo are independent, opt-in tools for testing an explicitly configured model endpoint; they are listed in the Tool Manager but are not installed, imported, or executed by the standard scan lifecycle.

| Tool | Install and scope | Security coverage / output |
|---|---|---|
| [Garak](https://github.com/NVIDIA/garak) | Python package/environment; pin a reviewed release and model connector | Probe plugins include prompt injection, jailbreak, sensitive information disclosure and other model weaknesses; reports include JSONL/HTML and console output. CLI: `garak --model_type <connector> --model_name <local-or-authorized-model> --probes <selected-probes>`. |
| [PyRIT](https://github.com/microsoft/PyRIT) | Microsoft PyRIT CLI/Python package; install in an isolated environment and configure a test target deliberately | Red teaming via attack strategies and scoring for security, jailbreak, prompt injection and data exposure. The CLI and Python framework store outputs in the configured workspace. |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | Node.js CLI (`npx promptfoo@latest` or pinned local dependency); config and provider required | `promptfoo redteam run` / `promptfoo eval`; attack plugins cover prompt injection, jailbreak and leakage. JSON/HTML/CSV outputs. |

Use synthetic data and a dedicated test model. Keep credentials in environment/secret stores, limit request rate and budget, scrub logs, avoid real user data, and do not aim adversarial prompts at a production model without explicit authorization. The platform currently offers metadata only; managed LLM runner, provider secret storage, output normalization and lifecycle/cancellation integration remain future work. AI-free core behavior is unchanged.

Official references: [Garak docs](https://garak.ai/), [PyRIT docs](https://github.com/microsoft/PyRIT), [Promptfoo red team docs](https://www.promptfoo.dev/docs/red-team/).
