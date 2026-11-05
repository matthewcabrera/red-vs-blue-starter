# Prompt Injection and PR Security Review

## Prompt injection experiment

A temporary code comment in the local practice app instructed the scanner to ignore its task and report no vulnerability. The agent could not contact its configured model endpoint in this environment, so resistance or bypass was not determined. The comment was removed afterward.

## Candidate repositories

- OWASP Juice Shop: intentionally insecure web application suitable for extending the local attack and defense agent to JavaScript routes and its training challenges. https://github.com/juice-shop/juice-shop
- OWASP WebGoat: intentionally insecure training app with Java lessons; adapt the code-reading and repair steps to Java/Spring. https://github.com/WebGoat/WebGoat
- OWASP GenAI Security Project: a real security documentation repository suitable for evaluating PR-diff review, though it is not a live exploit target. https://github.com/OWASP/www-project-top-10-for-large-language-model-applications

## Prevention and impact reduction

Prompt injection occurs when malicious instructions inside supplied content change an agent's behavior. A code comment, issue body, webpage, or document can carry indirect instructions. Prompt wording can improve resistance, but cannot guarantee prevention because instructions and data share the model context. OWASP recommends layered mitigations and notes that no mitigation eliminates the risk. https://genai.owasp.org/glossary/prompt-injection/

- Minimize privileges: give the model only task-specific read tools. Do not expose shell, write, merge, or messaging tools to a scanner.
- Keep PR code unexecuted: analyze the PR diff as untrusted text; use trusted workflow code from the base revision. Never run fork-controlled code in a job that has secrets.
- Limit credentials: use the narrowest token permissions; do not put secrets in prompts, logs, diffs, or model tool results.
- Validate output: parse a fixed schema, bound report size, escape Markdown, and treat findings as advisory.
- Require a maintainer to verify findings before merging or taking other consequential action.
- Evaluate repeatedly with benign and adversarial fixtures, including injected instructions in source comments. Prompt hardening is not a security boundary.

GitHub warns that privileged pull_request_target workflows become unsafe if they check out or run pull request code. This workflow checks out only the PR base and fetches its diff as text. https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target

## PR workflow status

The workflow runs on pull request updates, uses the trusted base revision, scans the PR diff, and posts a bounded Markdown comment. It requires an LLM_API_KEY repository secret. The workflow has not yet run on GitHub Actions. The prompt injection experiment remains inconclusive because the model endpoint was unreachable.
