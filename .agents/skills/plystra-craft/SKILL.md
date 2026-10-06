---
name: plystra-craft
description: "Plystra Craft baseline for every Plystra project in any medium. Use for any work in a Plystra-owned or sub-brand project: product behavior, writing and public claims, documentation, releases and maintenance status, user data and privacy notices, licensing and ownership wording, and the PROJECT_PRINCIPLES.md adoption record. Always installed; plystra-craft-code, plystra-craft-design, and plystra-craft-website add rules for those surfaces."
---

# Plystra Craft

The shared standard every Plystra project follows, whatever it is made of. Surface modules add rules on top of this skill; they never replace it.

## Which Plystra skills this project needs

| Skill | Install when the project… |
| --- | --- |
| `plystra-craft` | is a Plystra-owned project, a sub-brand, or a project under one. Always. |
| `plystra-craft-code` | contains source code: an app, service, library, CLI, script, or firmware. |
| `plystra-craft-design` | has a visual identity or an interface people see or operate: app UI, website, print, or physical design. |
| `plystra-craft-website` | operates an official website or public web documentation. |
| `plystra-craft-stewardship` | is where Plystra itself decides admission, sponsorship, or sub-brands. Not for ordinary projects. |

If a task touches a surface whose module is missing, such as interface work without `plystra-craft-design`, tell the user which module applies and give the command, for example `bunx --bun skills add plystra/craft --skill plystra-craft-design`. Do not guess that module's rules.

## Apply the standard

Read [applying Craft](references/applying-craft.md) before relying on any other reference. It defines `must`, `should`, and `may`, which provisions apply to which media and surfaces, and what the project's adoption record contains. Owned projects, sub-brands, and their projects follow every applicable requirement. A sponsored project follows only what it adopted, plus the sponsorship rules.

These standards describe how work should be done. They do not authorize publishing, deploying, contacting people, or changes outside the user's request.

## Read what the task needs

| Task | Read |
| --- | --- |
| Product purpose, workflows, automation or AI status, confirmations, maturity labels | [product](references/product.md) |
| Any user-facing text: descriptions, taglines, public claims, labels, empty states, errors | [writing](references/writing.md) |
| Positioning, voice, the five words, relationship wording such as "A Plystra project" | [brand](references/brand.md), [Plystra scope](references/plystra-scope.md), [charter commitments](references/charter-commitments.md) |
| Repository files, README, guides, `AGENTS.md`, examples, status labels | [documentation](references/documentation.md), [README template](assets/templates/project-readme.md) |
| Collecting real user data, telemetry, support data, or sending private content to an AI provider or other processor | [privacy and data](references/privacy-and-data.md), before collection or transfer begins |
| Releases, deprecation, compatibility, maintenance state, support, retirement, public launch | [release and maintenance](references/release-and-maintenance.md), [release notes template](assets/templates/release-notes.md) |
| Ownership records, licenses, contribution rules, naming and trademarks, terms of use | [ownership, licensing, and claims](references/ownership-licensing-claims.md) |
| Creating or updating `PROJECT_PRINCIPLES.md` | [applying Craft](references/applying-craft.md), [project principles template](assets/templates/project-principles.md) |
| A consequential decision worth preserving | [documentation](references/documentation.md), [decision record template](assets/templates/decision-record.md) |

Inspect the project's existing records, README, and `PROJECT_PRINCIPLES.md` before changing them. Replace template placeholders and links with real project facts and destinations.

## Report honestly

State what was checked and what remains unverified. Separate current behavior from plans. Completing a task, or keeping an adoption record, does not make a project fully compliant; only the review described in [applying Craft](references/applying-craft.md) establishes status.

The references are generated snapshots of the canonical Craft sources. The [index](references/index.md) lists each one with its source, and the [source ledger](references/sources.json) records the version and hashes. Keep the [license](references/LICENSE) when reusing them.
