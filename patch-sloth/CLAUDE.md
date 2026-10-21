# Patch Sloth: notes for Claude Code

- `SPEC.md` is the source of truth. Read it fully before starting, then work milestone by milestone (§15).
- Stop at any step tagged **[HUMAN]**.
- Wherever the spec says **VERIFY**, check third-party APIs against their docs or `--help` before writing code.
- Log every decision in `DECISIONS.md`, one line each with the date and the reason.
- Never commit secrets. Entire stores session transcripts in git.
- Respect the leakage rules in SPEC §8.4. Do not change the label rule (§8.2) without the human's approval.
- Do not overstate results. Every claim has to be backed by a file in `results/`.
