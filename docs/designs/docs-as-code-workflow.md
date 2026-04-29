# Docs-as-Code Workflow
**Version:** 1.0.0
**Status:** Accepted

---

## 1. Introduction

### Objective

Establish a lightweight, terminal-native workflow that keeps documentation and
source code in sync, version-controlled, and useful after the fact — without
adding tooling friction.

### Scope

This document covers:

- Which documents to create, and when.
- Where those documents live in the repository.
- How documents connect to commits, issues, and releases.
- How to select the right workflow for a given change.

It does not cover: API reference generation, public-facing documentation
sites, or team-scale review processes.

---

## 2. System Architecture

### 2.1 Top-level overview

The workflow has three layers. Each layer answers a different question.

```
┌─────────────────────────────────────────────────────┐
│  LAYER 3 — PERMANENT RECORD                         │
│  docs/adr/   docs/designs/   docs/plans/            │
│  "Why was it built this way?"                       │
├─────────────────────────────────────────────────────┤
│  LAYER 2 — IN-FLIGHT TRACKING                       │
│  GitHub Issues · Pull Requests                      │
│  "What is being changed and why?"                   │
├─────────────────────────────────────────────────────┤
│  LAYER 1 — CHANGE LOG                               │
│  Git commits (Angular convention)                   │
│  "What changed?"                                    │
└─────────────────────────────────────────────────────┘
```

Each layer is built on the one below it. A commit references an issue; an
issue references a document; a document is committed alongside the code.

### 2.2 Components

#### Tools

| Tool | Role |
|---|---|
| **Git** | Version control for both source code and documentation |
| **GitHub Issues** | Tracks motivation and design for in-flight changes |
| **GitHub CLI (`gh`)** | Terminal-native interface to Issues and Releases |
| **Markdown** | Plain-text format for all documents (rendered by GitHub) |

#### Document types

| Type | Location | Purpose | Lifespan |
|---|---|---|---|
| **Commit message** | Git history | Records what changed | Permanent |
| **GitHub Issue** | GitHub Issues tab | Records motivation while change is in flight | Closed on merge, permanent record |
| **Implementation plan** | `docs/plans/` | Ordered steps to execute a change | Permanent after execution |
| **Design document** | `docs/designs/` | Before/after structure, trade-offs, migration path | Permanent |
| **Architecture Decision Record (ADR)** | `docs/adr/` | Single architectural decision, context, and consequences | Permanent, never deleted |
| **`BUILDING.md`** | Repo root | How to build and run the project locally | Living document |
| **`ARCHITECTURE.md`** | Repo root | High-level system overview | Living document |

#### Repository layout

```
repo-root/
  BUILDING.md
  ARCHITECTURE.md
  docs/
    adr/
      001-<decision-slug>.md
      002-<decision-slug>.md
    designs/
      <feature-slug>.md
    plans/
      <YYYY-MM>-<feature-slug>-v<N>.md
    benchmarks/
      <YYYY-MM>-<feature-slug>.md     ← perf commits only
```

### 2.3 How components relate

```
GitHub Issue (motivation)
    │
    ├── referenced by → Git commits ("feat: ... (#12)")
    │                       │
    │                       └── closes → Issue (on merge)
    │
    └── resolved by → docs/designs/ or docs/plans/
                          │
                          └── key decision extracted to → docs/adr/
```

An ADR is the terminal artifact — it outlives the issue and the plan and
remains the authoritative record of why the system is the way it is.

---

## 3. Workflow Description by Case

### Case A — Small, self-contained change

**Applies to:** `style`, `fix`, `test` (additions), `chore`, `revert`

No document required beyond the commit message. The commit message must be
sufficient to explain the change to a reader with no other context.

```
fix: handle null IV in CBC mode when header byte is 0x00

The decrypt path assumed IV was always non-null after header parsing.
A crafted input with a zeroed IV field passed validation and caused
a segfault in the XOR step. Added explicit null-check before use.
```

**Artifacts produced:** commit message only.

---

### Case B — Motivated change with defined scope

**Applies to:** `feat` (contained), `refactor` (single module), `ci`, `build`,
`perf` (minor)

Open a GitHub Issue before writing any code. Reference it in every related
commit. Close it with the final commit.

```bash
# Open issue from terminal
gh issue create --title "refactor: consolidate GTest fetch to top-level CMake"

# Commit referencing the issue
git commit -m "refactor: remove per-target FetchContent declarations (#34)"

# Final commit closes the issue
git commit -m "docs: update BUILDING.md for new test layout (closes #34)"
```

**Artifacts produced:** GitHub Issue, commit messages.

---

### Case C — Structural change spanning multiple modules

**Applies to:** large `refactor`, multi-module `feat`, significant `perf`,
pipeline redesign (`ci`, `build`)

Open a GitHub Issue. Write a design document in `docs/designs/` as the first
commit. The design captures current structure, target structure, motivation,
and migration path. Commit the code in small steps. Extract any binding
decision into an ADR as the final step.

```bash
gh issue create --title "refactor: restructure test module (#34)"

# First commit: the design
cp draft.md docs/designs/test-module-refactor.md
git add docs/designs/test-module-refactor.md
git commit -m "docs: design for test module refactor (#34)"

# Code commits
git commit -m "test: create tests/ directory and shared fixtures (#34)"
git commit -m "test: migrate crypto module tests (#34)"
git commit -m "test: migrate CLI module tests (#34)"

# Final commit: close issue, add ADR if warranted
git commit -m "docs: ADR 005 — test directory structure (closes #34)"
```

**Artifacts produced:** GitHub Issue, `docs/designs/<slug>.md`,
optionally `docs/adr/00N-<slug>.md`.

---

### Case D — Architectural decision

**Applies to:** new dependency management strategy, new language introduced,
fundamental change to build or deploy model, security-critical design choice

Open a GitHub Issue. Write an ADR directly — the ADR *is* the design
document for decisions of this weight. Implementation plan goes in
`docs/plans/` if the execution is non-trivial.

ADR format:

```markdown
# ADR 003 — Binary artifact decoupled from security-portfolio

## Status
Accepted

## Context
The compiled image-encryptor binary was committed directly to
security-portfolio. Optimizations to cipher-fortis required a workflow
that avoids re-committing the binary on every change.

## Decision
Publish the binary as a GitHub Release asset from cipher-fortis CI.
The security-portfolio Dockerfile downloads a pinned version by tag.

## Consequences
- Upgrading the binary requires a tag in cipher-fortis and a one-line
  Dockerfile change in security-portfolio.
- The build environment in cipher-fortis CI must match the Docker base
  image glibc version to avoid runtime linkage failures.
- Implicit: the cipher-fortis repo must be public, or a deploy key
  must be configured for private access.
```

ADRs are **never rewritten**. If a decision is reversed, a new ADR is written
with status `Supersedes ADR 00N`.

**Artifacts produced:** GitHub Issue, `docs/adr/00N-<slug>.md`,
optionally `docs/plans/<date>-<slug>-v<N>.md`.

---

### Case E — Performance change in a security-critical tool

**Applies to:** `perf` commits in `cipher-fortis`

All performance changes require benchmark results committed alongside the
code, and a brief note on whether constant-time properties are affected.

```bash
git commit -m "perf: use AES-NI intrinsics in CBC encrypt path (#41)"
# docs/benchmarks/2025-04-aes-ni-cbc.md must be included in this commit
```

Benchmark document minimum content:

```markdown
## Benchmark — AES-NI CBC encrypt path

**Date:** 2025-04-25
**Commit:** <hash>

| Input size | Before | After | Delta |
|---|---|---|---|
| 1 MB | 142 ms | 38 ms | −73% |

**Constant-time impact:** None. AES-NI instructions execute in
data-independent time on all target microarchitectures.

**Reference:** Intel® 64 and IA-32 Architectures Optimization Manual,
section 12.7.
```

**Artifacts produced:** GitHub Issue, `docs/benchmarks/<date>-<slug>.md`,
optionally an ADR if the change introduces a new algorithmic approach.

---

## 4. Workflow Selection Criteria

Ask the following questions in order. Stop at the first match.

```
1. Does this change cross module boundaries, introduce a new abstraction,
   or constrain future design choices?
   YES → Case D (ADR) or Case C (design doc), depending on scope.

2. Is this a performance change in cipher-fortis?
   YES → Case E (always, regardless of size).

3. Does this change have a motivation that a commit message cannot
   fully express?
   YES → Case B (Issue) or Case C (Issue + design doc).

4. Is the change self-contained, easily reversible, and self-explanatory?
   YES → Case A (commit message only).
```

As a secondary check — if the change goes wrong or needs to be revisited in
six months, will you wish you had written down your reasoning? If yes, write
a document.

---

## 5. Quick Reference

| Change type | Case | Minimum artifacts |
|---|---|---|
| Style, formatting | A | Commit message |
| Bug fix (isolated) | A | Commit message |
| Test addition | A | Commit message |
| Chore, revert | A | Commit message |
| Contained feature | B | Issue + commit messages |
| Single-module refactor | B | Issue + commit messages |
| CI/build change | B or C | Issue; + design doc if pipeline changes significantly |
| Multi-module refactor | C | Issue + design doc + optional ADR |
| Large feature | C | Issue + design doc + optional ADR |
| Architectural decision | D | Issue + ADR + optional plan |
| Any perf in cipher-fortis | E | Issue + benchmark doc + optional ADR |

---

## 6. Definitions

**ADR (Architecture Decision Record):** A short document capturing a single
architectural decision, its context, and its consequences. Never deleted;
superseded by a new ADR when reversed.

**Constant-time:** A property of a cryptographic implementation where
execution time does not depend on secret data values, preventing
timing-based side-channel attacks.

**Design document:** A document describing the current and target structure
of a component, the motivation for changing it, and the migration path.
Written before implementation begins.

**Docs as Code:** The practice of treating documentation with the same
discipline as source code — version-controlled, reviewed, and updated
alongside the code it describes.

**Implementation plan:** An ordered sequence of phases for executing a
change, each with a verification gate and rollback strategy.

**Dev/Prod Parity:** The principle (Twelve-Factor App, factor 10) that
development, CI, and production environments should be as similar as
possible to prevent environment-specific failures.

**glibc:** The GNU C Library. The version compiled against during build must
be less than or equal to the version available at runtime, or the executable
will fail to load.

**Infrastructure as Code (IaC):** The practice of declaring build
environments, pipelines, and runtime configuration as version-controlled
text files rather than manual procedures.
