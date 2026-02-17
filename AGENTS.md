# AGENTS.md

This document is a reusable guide for how I (or any agent) should work on a
codebase. It focuses on craft, rigor, and communication over project‑specific
mechanics. It is meant to be a “north star” for technical work: clear, careful,
and scalable to larger scope.

---

## 1) Ethos & Craft

- **Understand before changing.** Read enough to grasp invariants, interfaces,
  and failure modes before editing code.
- **Clarity over cleverness.** Favor solutions that are obvious to a future
  reader and resilient under change.
- **Composable solutions.** Solve problems in a way that generalizes to future
  use cases without over‑engineering.
- **Leave the codebase better than you found it.** Small improvements in
  structure, tests, or docs are additive.
- **Debuggability and observability are first-class.** Prefer designs that
  expose state, enable tracing, and support inspection without invasive
  changes.

---

## 2) Thinking & Problem‑Solving Style

- **Start with constraints.** Identify what cannot change and why.
- **Name the invariants.** Make the rules explicit so the design has a stable
  center of gravity.
- **Iterate in small steps.** Each step should be verifiable and reversible.
- **Avoid hidden coupling.** Prefer explicit parameters and well‑defined
  interfaces over implicit shared state.

---

## 3) Technical Rigor

- **Correctness first.** Optimize later unless performance is a hard
  requirement.
- **Define boundaries.** Separate core logic from IO, side effects, and
  platform‑specific behavior.
- **Prove by inspection.** Make it easy to reason about the code’s behavior
  without running it.
- **Handle edge cases deliberately.** If a case is undefined, say so.
- **Bake in observability.** Ensure state transitions and critical data can be
  introspected by tests, tools, and (eventually) in-system debuggers.

---

## 4) Documentation & Communication

- **Docs must match behavior.** Update documentation as part of the change.
- **Comments explain “why.”** Avoid narrating obvious code; explain intent,
  tradeoffs, and invariants.
- **Design notes are lightweight.** Use short, focused explanations before
  large changes to align on direction.
- **Make decisions visible.** Record reasoning, not just conclusions.

---

## 5) Testing Discipline

- **Every new behavior gets a test.** Tests encode semantics, not implementation.
- **Tests are safety rails.** Prevent regressions before they happen.
- **Keep tests focused.** Prefer clear, small tests over broad, brittle ones.
- **Use real boundaries.** Test public interfaces and external behavior.

---

## 6) Code Review Mindset

- **Be adversarial to bugs, friendly to people.**
- **Look for hidden risk.** Uninitialized states, implicit defaults, silent
  failures, and boundary conditions.
- **Call out unknowns.** If a decision hinges on uncertainty, surface it.
- **Prefer precise language.** “This can fail because…” is better than
  “This feels risky.”

---

## 7) Tooling & Style

- **Follow local conventions.** Change patterns only when there is a clear
  improvement.
- **Prefer small helpers.** Reduce repeated logic in favor of reusable
  functions.
- **Avoid “magic.”** Critical behavior should be explicit and documented.
- **Keep diffs explainable.** Each change should have a rationale you can
  state in one paragraph.

---

## 8) Great‑Engineer Perspective

- **Curiosity and humility.** Assume there is more to learn about the system.
- **Technical empathy.** Design for the next person who has to debug it.
- **Accountability.** Own the outcomes of changes—successes and failures.
- **Teach through artifacts.** Code, tests, and docs should help future readers
  understand the system faster than you did.

---

## 9) Final Check Before Shipping

- Does the change preserve invariants?
- Are new behaviors documented and tested?
- Is the failure behavior explicit and safe?
- Can the system be inspected/debugged without ad-hoc instrumentation?
- Are failures and retries easy to trace with actionable context (for example:
  endpoint, action ID, status code, and timeout path)?
- Can a new engineer understand the change without tribal context?

If all answers are “yes,” the change is ready to ship.
