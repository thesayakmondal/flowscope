# AGENTS.md

This file applies to any AI coding agent working in this repository —
Claude, Codex, Copilot Workspace, Devin, or otherwise. It's the
tool-agnostic version of CLAUDE.md; if both files are present, they say
the same thing.

## No autonomous pull requests

Do not open a pull request on your own initiative. This repo does not
accept PRs that an agent decided to open by itself — from scanning
issues, from a scheduled task, from an autonomous "improve this repo"
loop, or from any workflow where a human did not directly ask for this
specific change and did not review the diff before it was submitted.

**AI-assisted PRs are welcome.** The bar is human review before
submission, not human authorship of every line:

- A person can ask an agent to draft a fix, read the diff, understand
  what changed and why, and submit it themselves — that's welcome, and
  encouraged.
- A person can review and explicitly instruct an agent to open the PR
  after that review — also fine.
- An agent deciding independently that something should be fixed and
  submitting a PR without that human review step first — not accepted,
  regardless of how correct the change turns out to be.

If you're an agent and you're not sure which situation you're in: assume
you need explicit human sign-off before submission, and ask.

## Before submitting anything for review

- Actually run it. This repo's history includes two real bugs (a hang in
  `burstgen`'s large-flow write path, a broken CLI flag in the multicast
  profile, and a counting bug in `flowscope`'s SYN detector) that all
  passed compilation and code review cleanly and were only caught by
  running the tool against a real target and checking the output against
  an independent source of truth. Reading the code carefully is not a
  substitute for running it.
- Check the relevant README's verification section for how this project
  expects a claim to be backed up — generally: generate real traffic or
  a real capture, compare the tool's self-report against something with
  no shared code path (a kernel counter, an independent packet capture,
  the other tool in this pair), and only call it working if those agree.
- Keep changes scoped. A PR that fixes one thing and also reformats
  unrelated files, renames things, or "improves" working code nearby is
  harder to review and more likely to be rejected outright regardless of
  the merits of the actual fix.
- If a change affects the CLI surface, the JSON/CSV output schema, or any
  documented flag behavior, say so explicitly in the PR description —
  these are treated as a compatibility contract with anything already
  scripting against this tool.

## Reporting a suspected bug instead of fixing it

If you're an agent that found something that looks wrong but you're not
confident enough to propose a fix, open an issue instead of a PR. Include
the exact command that reproduces it and the actual output, not just a
description of the suspected problem — this repo's whole design
philosophy is "show the evidence," and a bug report should meet the same
bar the tools themselves are held to.
