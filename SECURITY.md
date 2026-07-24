# Security policy

Do not open a public issue containing a vulnerability, credential, private
repository content, or personal data. Report sensitive findings privately to
the repository owner through GitHub's private vulnerability reporting feature.

DevFlow treats issues, source code, retrieved text, tool output, and model
responses as untrusted input. Expected invariants include:

- credentials never enter prompts, logs, commits, or evidence artifacts;
- repository writes remain branch-scoped and repository-relative;
- candidate execution occurs only in isolation;
- red CI and high/critical findings block promotion;
- T4 and T5 changes require recorded human approval;
- inter-agent artifacts are versioned and integrity checked.

Include affected version, reproduction steps, impact, and a proposed
containment measure. Do not include real secrets in a proof of concept.

