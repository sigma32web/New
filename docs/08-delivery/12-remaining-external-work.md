# Remaining external work

What is left after the credential-free automated tranche. Everything here is blocked on something this
repository cannot contain: a paid provider, a deployed environment, a secret manager, or a human.

This file is deliberately short. If an item can be done locally and deterministically, it does not belong
here — it belongs in the backlog as work to do.

**Phase 4 is NOT complete, and the MVP is not production ready.** The milestone this tranche targets is
*automated readiness*: the practical credential-free implementation, simulation and validation that should
exist before the live tranche begins.

## Blocked on a live provider

| Item | Why it cannot be done here | What is already prepared |
| --- | --- | --- |
| Live-provider connectivity and prose quality | needs paid API access | `HttpProvider` speaks the real transport; `YEONJAE_PROVIDER_MODE=live` is a validated mode |
| Confirmed REMOTE cancellation | only a real provider can acknowledge a stop | the `/v1/cancel` path and `remote_cancellation` states (`acknowledged` / `unsupported` / `unknown` / `not_requested`) are exercised against the simulator |
| Proof that remote provider computation stopped | not observable without provider cooperation | recorded as `unknown` by construction; never claimed |
| Real provider outage and fallback drills | needs an actual outage | 49 deterministic chaos scenarios plus HTTP 429/500/502/503, resets and truncation against the simulator |
| Provider usage and invoice reconciliation | needs invoices | integer-millicent accounting, `cost_known`, and unknown-cost settlement that never books zero |
| Five-night live chapter campaign | needs paid generation over five nights | the 120-chapter deterministic replay |

## Blocked on deployed infrastructure

| Item | Why it cannot be done here | What is already prepared |
| --- | --- | --- |
| Staging and production deployment | no environment exists | readiness gates on migration state, schema drift and role attributes |
| Staging/production restore and real PITR | needs a deployed database and WAL archive | local deterministic logical dump/restore with 40 invariants, including security metadata and re-executed post-restore behaviour |
| Production monitoring observation | needs a running deployment scraping `/metrics` | per-process Prometheus registry with a STRICT metric-label allowlist, plus `ops/alerts.json` and `ops/dashboards.json` validated against that registry. **Nothing observes them**; no alert has ever fired |
| The privilege model verified on a deployed cluster | needs that cluster | ADR-0050's model asserted against local PostgreSQL 16 and in fork CI |
| **Building and running** the container topology | **no container runtime is available in this workspace** — `docker` and `podman` are both absent | `deploy/Dockerfile`, `deploy/.dockerignore` and `deploy/compose.yaml` exist and are **statically validated** by 32 tests (stage graph, dependency conditions, published ports, credential defaults, health paths checked against real routes, secret scan). They have **never been built or run** |

## Blocked on a real secret manager

| Item | Why it cannot be done here | What is already prepared |
| --- | --- | --- |
| Live credential rotation | rotating a credential requires having one | rotation runbooks; `.env.example` lists variable names only; gitleaks gate over full history |

## Blocked on human judgment

| Item | Why it cannot be done here | What is already prepared |
| --- | --- | --- |
| Bilingual human review | needs reviewers | blinded reviewer-packet tooling |
| Evaluator threshold calibration | needs review outcomes | 100-set corpus, 2,000 deterministic evaluations, 700/700 agreement, status `uncalibrated` |
| Product-owner acceptance | a decision, not a task | — |

## Not blocked, and honestly still open

Recorded here so the list above cannot be read as "everything else is done". These are credential-free and
could be implemented next. The previous entries for shared enforcement, local embeddings, versioned vector
retrieval, the thesaurus, multi-process tests, metrics and deployment/alert templates have been **removed
because they are now implemented** (see `09-progress.md`).

- **Health, readiness and graceful shutdown completion.** Readiness already fails closed on migration
  state, schema drift and role attributes, and the worker now drains its Temporal connection and pool on
  every exit path. Not done: a worker liveness/readiness endpoint of its own, an explicit API drain phase
  with a bounded deadline, telemetry flush on shutdown, and a declared degraded-versus-unavailable
  distinction for optional dependencies.
- **Operator API and CLI surfaces for the new subsystems.** The controls exist as library functions with
  tests (rate-limit status, budget status, embedding-set activation and rollback, retrieval diagnostics,
  thesaurus expansion diagnostics), and the operator `/v1` and CLI surfaces that would expose them have
  **not** been added.
- **Metric call sites.** The metric names, help text, label allowlist and cardinality tests exist and are
  validated against the alert and dashboard templates. The new counters are **not yet incremented from the
  gateway, worker and retrieval paths**; only the pre-existing API metrics have live call sites.
- **The remaining deterministic workflow surfaces** listed in `02-backlog.md` (batch operations,
  regeneration preview, typography and platform-format checks, deterministic export preparation).
- **Local recovery completion beyond the current 40 invariants:** a backup manifest with migration hashes
  and checksums, injected-failure cases (truncated backup, checksum mismatch, missing migration,
  interrupted restore), and a local-only WAL/PITR rehearsal harness.
- **Credential-rotation simulation** with generated fake credentials: key identifiers, overlap windows,
  retired-credential rejection, rollback, and a fake local secret-manager adapter.
- **Bounded performance smoke tests** (concurrent API requests, shared admission and reservation
  throughput, retrieval latency, N+1 and index checks).
- **One full deterministic end-to-end automated-readiness scenario** wiring all of the above together in a
  single run with a no-skip guard.
