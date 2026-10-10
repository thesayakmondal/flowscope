# Contributing

Thanks for considering a contribution. A few things to know before
opening an issue or a PR.

## AI-assisted contributions

Using Claude, ChatGPT, Copilot, or any other AI tool to help write a
contribution is fine and welcome.

What's not accepted is a **fully autonomous** PR — one where an AI agent
decided on its own that something should change, wrote the change, and
submitted it without a human reading the diff first. See
[AGENTS.md](./AGENTS.md) and [CLAUDE.md](./CLAUDE.md) for the exact
policy if you're running an agent against this repo; the short version:
AI-assisted is welcome, AI-autonomous is not. If a maintainer notices a
PR that looks like it skipped human review, it will be closed and the
submitter asked to review it themselves and resubmit.

## Before opening a PR

1. **Run it.** Every claim this project makes about a tool's behavior is
   backed by an actual run against a real target, cross-checked against
   an independent source of evidence (see each tool's README for its
   verification section). A change that compiles but wasn't run against
   anything real is not ready for review.
2. **Keep it scoped.** One fix per PR. Don't bundle a functional change
   with a reformat, a rename, or an unrelated cleanup — it makes the
   actual fix harder to evaluate and more likely to get bounced back.
3. **Explain the "why," not just the "what."** Most files in this repo
   carry doc comments explaining the reasoning behind a design choice,
   not just what the code does. If your change contradicts one of those
   comments, either the comment is now wrong (say so, and update it) or
   your change is missing something the original design accounted for —
   figure out which before submitting.
4. **Flag contract changes.** If your PR changes a CLI flag's behavior,
   the JSON/CSV output schema, or anything else something else might
   already be scripting against, call that out explicitly in the PR
   description.

## Reporting bugs

Open an issue with:
- The exact command you ran
- What you expected vs. what actually happened
- If possible, independent evidence the behavior is wrong — a kernel
  counter, a packet capture, a second tool's disagreeing output — the
  same standard this project holds its own findings to. "It doesn't feel
  right" is a fine starting point, but a reproducible, evidenced report
  gets fixed faster.

## Code style

Match what's already there: doc comments on every public item explaining
*why*, not just *what*; small, single-purpose modules; explicit error
handling with `anyhow::Context` rather than `.unwrap()` outside of tests.
No enforced formatter config beyond `cargo fmt` defaults — run
`cargo fmt` and `cargo clippy` before submitting.
