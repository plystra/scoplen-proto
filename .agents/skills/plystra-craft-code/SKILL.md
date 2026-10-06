---
name: plystra-craft-code
description: "Plystra Craft rules for projects that contain code. Use when implementing, debugging, reviewing, testing, or deploying software in a Plystra project: architecture, repository files, configuration and secrets, data and migrations, APIs, auth, security, dependencies, verification, and definition of done. Requires plystra-craft."
---

# Plystra code

Rules for the software in a Plystra project. They add to `plystra-craft`, which carries the shared product, writing, documentation, privacy, release, and licensing standards. If `plystra-craft` is not installed, tell the user to run `bunx --bun skills add plystra/craft --skill plystra-craft`.

## Every code change

Follow [code working standards](references/code-working-standards.md): trusted guidance and authorization, context gathering, scoped edits, dependencies, git hygiene, verification through public surfaces, review, deployment, and the definition of done.

Read the target repository's own guidance, worktree state, and existing commands before editing. Never deploy, publish, push, or merge without an explicit request.

## Read what the change touches

| Change | Read |
| --- | --- |
| Architecture, configuration, data and migrations, APIs, errors, dependency choice, test strategy, observability, AI features | [engineering standards](references/engineering-standards.md) |
| Secrets, authentication, authorization, input handling, payments, logging | [security](references/security.md) |
| User data collection, AI providers, export or deletion | `plystra-craft`: privacy and data |
| Repository files, README, contributor and agent guidance | `plystra-craft`: documentation |
| Deploying a service or site | [code working standards](references/code-working-standards.md); release notes live in `plystra-craft` |
| Visible interface | `plystra-craft-design`, if installed |

Do not turn an ordinary fix into a full security or release audit. Report what changed, what was verified, and what could not be.

The [index](references/index.md) and [source ledger](references/sources.json) identify the canonical sources of this snapshot. Keep the [license](references/LICENSE) when reusing them.
