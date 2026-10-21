# Decisions

One line per decision: date, decision, reason.

- 2026-10-21 · Keep the nested layout (git root `patch-sloth/`, project in `patch-sloth/patch-sloth/`); run every command from the inner folder · the scaffold was committed that way and the scripts use relative `data/` and `results/` paths.
- 2026-10-21 · Dev env is conda `patchsloth` (Python 3.11) on a CPU-only Windows laptop; GPU work (TabPFN, vLLM) runs on the workstation · this is the human's setup for M0/M1/M5-CPU.
- 2026-10-21 · Split `tabpfn` (and torch) into `requirements-gpu.txt` · avoids pulling a large CPU torch build onto the laptop; nothing on the CPU path imports TabPFN.
- 2026-10-21 · Label rule moved verbatim to `patchsloth/data/nvd.py:label_vector` as a pure function using `isinstance(x, str)` · keeps the rule unit-testable (SPEC §8.2, regression test for the NaN bug).
- 2026-10-21 · `FeatureBuilder` uses a sorted vocabulary of the train top-40 CNAs/CWEs plus `"other"`, instead of `pd.Categorical(...)` over the scored frame · the codes must not depend on which rows are scored (train/serve parity). On the full dataset this reproduces the original codes exactly, because every top-40 value and "other" occur.
- 2026-10-21 · `HistGradientBoostingClassifier(random_state=0)` · SPEC §19 says seed all randomness with 0, and HGB's automatic early stopping draws a random validation split when n > 10k. This may move the HGB numbers slightly against the pre-refactor run.
- 2026-10-21 · `parse_output` takes the first JSON object in the text with all 8 valid fields (strips `<think>` blocks), instead of only the first line · more robust to extra text. `json_valid` still counts any fallback to the CNA vector as invalid.
- 2026-10-21 · Ruff rule set pinned to E/F/W/I/B/UP; E701/E702/E741/B905 ignored, plus E401/E501 in `scripts/` · the installed ruff's default set is far broader, and the scaffold's compact style is intentional. Real findings were fixed (unused imports, import order, loop-variable lambdas in `03`).
- 2026-10-21 · pip resolved pandas 3.0 (missing values in string columns are NaN, not None) · this is the NaN-bug shape, so `test_label_rule.py` exercises the rule through a DataFrame as well as with raw values.
- 2026-10-21 · `VLLMBackend` and `TinkerBackend` are stubs that raise `NotImplementedError` until M3/M6 · CPU-only night; `NullBackend` covers `--no-llm` and the tests.
