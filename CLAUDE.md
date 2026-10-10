# CLAUDE.md

Guidance for Claude (or any Claude-based coding agent) working in this
repository.

## Do not open autonomous pull requests

This repository does not accept pull requests opened autonomously by an
agent — i.e. an agent deciding on its own to branch, commit, and open a PR
without a human directly asking for that PR, reviewing the diff, and
choosing to submit it.

AI-assisted PRs are welcome. The distinction is about who is driving:

- **Welcome:** a human uses Claude (chat, Claude Code, or any other tool)
  to help write, debug, or review a change, reads the resulting diff
  themselves, understands it, and opens the PR themselves (or explicitly
  tells the agent to open it after review).
- **Not welcome:** an agent operating on its own initiative — scanning
  issues, deciding something should be fixed, writing the change, and
  submitting a PR without a human having read and approved the diff first.

If you are an agent with the ability to open PRs directly: don't. Prepare
the change, show the diff to the person you're working with, and let them
decide whether and how to submit it.

## Before proposing any change

- Read the relevant module's doc comments before editing it — most files
  in this repo explain *why* something is built the way it is, not just
  what it does. A change that looks like an obvious improvement without
  that context is often not one.
- Run the existing test/verification steps in README.md for anything you
  touch. A change that compiles is not the same as a change that works —
  this repo's own history includes real bugs (see README's "bugs found
  and fixed" section) that only surfaced through actual runtime testing
  against real targets, not from reading the code or from compilation
  succeeding.
- Prefer the smallest change that fixes the actual problem. Do not
  refactor unrelated code, rename things, or "clean up" style in the same
  change as a functional fix.
- If a fix changes CLI flags, output format, or file schemas (events.json,
  report.md), call that out explicitly — those are treated as part of the
  tool's contract with anyone scripting against it.

## What "thoroughly checked" means here

Before any change is presented as ready:
1. It builds clean (`cargo build --release`), no new warnings introduced.
2. It was actually run against a real target, not just read — for this
   repo specifically, "the logic looks right" is not sufficient; see the
   README's verification runbook for the pattern this project uses
   (generate real traffic/capture, compare against an independent source
   of truth, don't trust a single self-reported number).
3. Any new claim (a new counter, a new detector, a new correlation) is
   verified against something outside the tool's own code path — a raw
   kernel counter, an independently-captured packet, a second tool's
   output — the same way every existing feature in this repo was
   verified before being called done.
