/**
 * Structured logging, redaction and metrics (Checkpoint 7; observability plan §5).
 *
 * The plan's requirement is short and absolute: "Structured JSON; no manuscript/prompt text (IDs + hashes
 * only); correlation by trace ID". Implementing it as a *default-deny serializer* rather than a list of
 * things to strip is the whole design decision here, and it is worth stating why.
 *
 * A redaction blocklist fails in one direction: every new field is exposed until somebody remembers to add
 * it. For a system whose logs sit next to customer manuscripts, provider credentials and session secrets,
 * that default is the wrong way round — the first forgotten field is a leak, not a cosmetic bug. So
 * `logFields` accepts only an explicit allowlist of key shapes (ids, hashes, counts, enums, durations) and
 * replaces anything else with a type marker. A field nobody thought about is therefore absent from the log,
 * which is a recoverable mistake, instead of present, which is not.
 *
 * Metrics are an in-process registry rendered in Prometheus text format. That is honest about what it is:
 * per-process counters that reset when the process restarts and are scraped per instance. It is not a
 * distributed aggregation layer, and §5.2's dashboards assume a scraper doing the aggregation.
 */

/** Values a log field may carry once accepted. Deliberately narrow: no nested objects, no free text. */
export type LogValue = string | number | boolean | null;

/** The marker a rejected value is replaced with, so its absence is visible rather than silent. */
export const REDACTED = '[redacted]';

/**
 * Field names that are always dropped, regardless of shape.
 *
 * This list is NOT the mechanism — the allowlist below is — but it exists so a value that would otherwise
 * look like a harmless opaque string (a session token is, structurally, just a string) cannot slip through
 * on shape alone. Matching is on a normalized name, so `Authorization`, `authorization` and
 * `auth_header` are all caught.
 */
const FORBIDDEN_FRAGMENTS: readonly string[] = [
  'password',
  'passwd',
  'verifier',
  'secret',
  'token',
  'csrf',
  'cookie',
  'authorization',
  'auth_header',
  'api_key',
  'apikey',
  'session',
  'credential',
  'connection_string',
  'database_url',
  'dsn',
  'prompt',
  'manuscript',
  'text',
  'prose',
  'quote',
  'content',
  'body',
  'output',
  'input',
  'delta',
  'payload',
  'justification',
  'statement',
  'summary',
  'title',
  'email',
  'display_name',
];

/**
 * Field names that may carry a value, as exact names or `*_suffix` shapes.
 *
 * Everything here is an identifier, a hash, a count, a duration or a closed enum — the vocabulary §5.1
 * lists as span attributes. Note what is NOT here: anything that could contain prose, a credential or a
 * free-form message. `detail`-style fields are excluded on purpose; an operator-facing explanation belongs
 * in the RFC 9457 problem document sent to the client, not in a log line that may be shipped elsewhere.
 */
/**
 * Fragments that make a digest a CREDENTIAL digest rather than a content digest.
 *
 * The `_hash` carve-out below must not cover these: a password hash is the verifier an attacker cracks
 * offline, and a session or API-key hash is the stored form the server compares against, so either one is
 * security-relevant even though it is technically one-way.
 */
const CREDENTIAL_FRAGMENTS: readonly string[] = [
  'password',
  'passwd',
  'verifier',
  'secret',
  // Singular `token` only. `_token`/`token_` substring matching was tried and is wrong: `input_tokens`
  // contains `_token`, and those usage counts are required metrics (§5.2 `llm_tokens_total`). The
  // singular form still catches `csrf_token`, `session_token`, `bearer_token` and `token_hash`, because
  // every credential name uses the singular while every measure uses the plural.
  'token',
  'csrf',
  'cookie',
  'session',
  'api_key',
  'apikey',
  'credential',
  'authorization',
];

/** Suffixes that make a field a numeric measure of content rather than the content itself. */
const COUNT_SUFFIXES: readonly string[] = ['_tokens', '_count', '_cents', '_ms', '_bytes', '_size'];

const ALLOWED_EXACT: readonly string[] = [
  'action',
  'attempt',
  'basis',
  'canon_version',
  'chapter_no',
  'code',
  'control',
  'count',
  'duplicate',
  'duration_ms',
  'event',
  'fence',
  'format',
  'byte_size',
  'items',
  'kind',
  'latency_ms',
  'limit',
  'materiality',
  'method',
  'model_class',
  'origin',
  'outcome',
  'phase',
  'provider',
  'reason',
  'replayed',
  'result',
  'role',
  'route',
  'schema_valid',
  'seq',
  'source',
  'stale_marked',
  'status',
  'status_code',
  'step',
  'target_kind',
  'tier',
  'verb',
  'version',
  'version_no',
];

/** Suffixes that make a field an identifier, hash or counter rather than content. */
const ALLOWED_SUFFIXES: readonly string[] = ['_id', '_ids', '_hash', '_count', '_cents', '_tokens'];

/**
 * Whether a name denotes a credential rather than a measure of one.
 *
 * The plural/singular distinction does the work: `token` is a credential, `tokens` is a usage count. Naive
 * substring matching cannot express that — `input_tokens` contains `token` — so the plural measure
 * suffixes are stripped before the credential fragments are applied.
 */
function isCredentialName(normalizedKey: string): boolean {
  const stem = COUNT_SUFFIXES.reduce(
    (k, suffix) => (k.endsWith(suffix) ? k.slice(0, -suffix.length) : k),
    normalizedKey,
  );
  return CREDENTIAL_FRAGMENTS.some((f) => stem.includes(f));
}

function normalizeKey(key: string): string {
  return key.toLowerCase();
}

/** Whether a field name may appear in a log at all. Forbidden fragments win over the allowlist. */
export function isLoggableKey(key: string): boolean {
  const k = normalizeKey(key);
  /**
   * A `*_hash` field is a digest, and a digest of prose is not prose.
   *
   * This exception exists because the fragment rule alone rejects `content_hash` (it contains "content")
   * and `prompt_hash` (it contains "prompt") — exactly the two fields the observability plan §5.1 names as
   * required span attributes, and the whole point of "IDs + hashes only". The narrow carve-out is safe
   * precisely because a hash is one-way: it correlates without disclosing. Two limits keep it narrow: it
   * applies to the `_hash` SUFFIX rather than any occurrence of "hash", and it never applies to a
   * credential digest. `password_hash` is a verifier — the thing an attacker cracks offline — so it is not
   * covered, and neither is a session or API-key hash, which is the stored form the server compares
   * against and therefore as good as the secret for lookup purposes.
   */
  if (k.endsWith('_hash') && !isCredentialName(k)) return true;
  /**
   * Numeric measures of content are not content.
   *
   * `input_tokens` and `output_tokens` are required metrics (observability plan §5.2 `llm_tokens_total`),
   * yet they contain the fragments "input" and "output" that exist to block prompt and completion BODIES.
   * A token count cannot reconstruct prose, so the count suffixes are permitted while the bare `input` and
   * `output` keys stay refused. As with hashes, a credential measure is excluded.
   */
  if (COUNT_SUFFIXES.some((suffix) => k.endsWith(suffix)) && !isCredentialName(k)) return true;
  // Otherwise a name containing a forbidden fragment is refused even when its shape looks safe:
  // `session_id` is an identifier, yet logging it would let a log reader correlate a live session.
  if (FORBIDDEN_FRAGMENTS.some((f) => k.includes(f))) return false;
  if (ALLOWED_EXACT.includes(k)) return true;
  return ALLOWED_SUFFIXES.some((s) => k.endsWith(s));
}

/**
 * Project arbitrary fields into a safe log record.
 *
 * Rejected keys are dropped entirely rather than included as `[redacted]`: keeping the key would leak the
 * SHAPE of the data (that a password was involved, that a particular field exists) and would grow log lines
 * with no diagnostic value. A rejected VALUE under an allowed key becomes `[redacted]`, because there the
 * key itself is the useful signal and its absence would look like "not measured".
 */
export function logFields(fields: Readonly<Record<string, unknown>>): Record<string, LogValue> {
  const out: Record<string, LogValue> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (!isLoggableKey(key)) continue;
    out[key] = safeValue(value);
  }
  return out;
}

/** Accept only scalars; anything structured becomes a type marker so nested prose cannot ride along. */
function safeValue(value: unknown): LogValue {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    // A bounded length is the second half of "IDs + hashes only": an id or hash is short, so a long string
    // under an allowed key is a sign the field is carrying something it should not.
    return value.length <= 200 ? value : REDACTED;
  }
  // Arrays and objects are never rendered. A count is the useful, safe projection of a list.
  if (Array.isArray(value)) return value.length;
  return REDACTED;
}

export interface LogRecord {
  readonly level: 'debug' | 'info' | 'warn' | 'error';
  readonly msg: string;
  readonly request_id?: string | undefined;
  readonly trace_id?: string | undefined;
  readonly workspace_id?: string | undefined;
  readonly project_id?: string | undefined;
  readonly job_id?: string | undefined;
  readonly workflow_id?: string | undefined;
}

/**
 * Render one structured JSON log line.
 *
 * `msg` is a fixed developer-authored string, never interpolated with request data — an interpolated
 * message is exactly how prose and secrets end up in logs that were otherwise carefully structured.
 */
export function logLine(record: LogRecord, fields: Readonly<Record<string, unknown>> = {}): string {
  const base: Record<string, LogValue> = {
    level: record.level,
    msg: record.msg,
    ...(record.request_id ? { request_id: record.request_id } : {}),
    ...(record.trace_id ? { trace_id: record.trace_id } : {}),
    ...(record.workspace_id ? { workspace_id: record.workspace_id } : {}),
    ...(record.project_id ? { project_id: record.project_id } : {}),
    ...(record.job_id ? { job_id: record.job_id } : {}),
    ...(record.workflow_id ? { workflow_id: record.workflow_id } : {}),
  };
  return JSON.stringify({ ...base, ...logFields(fields) });
}

// ---------------------------------------------------------------------------------------------------------
// trace correlation
// ---------------------------------------------------------------------------------------------------------

/** W3C `traceparent`: `00-<32 hex trace id>-<16 hex span id>-<2 hex flags>`. */
const TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/;

/**
 * Extract an inbound trace id, or `undefined` when the header is absent or malformed.
 *
 * A malformed `traceparent` is IGNORED rather than passed through. Trace ids reach logs and the `llm_calls`
 * audit, so accepting an arbitrary client string would let a caller inject content into both — the same
 * class of problem as trusting a forwarded client IP. Strict parsing means the only ids that propagate are
 * ones that are structurally trace ids.
 */
export function traceIdFrom(traceparent: string | undefined): string | undefined {
  if (!traceparent) return undefined;
  const m = TRACEPARENT.exec(traceparent.trim().toLowerCase());
  const traceId = m?.[1];
  // An all-zero trace id is explicitly invalid in the W3C spec.
  if (!traceId || /^0+$/.test(traceId)) return undefined;
  return traceId;
}

// ---------------------------------------------------------------------------------------------------------
// metrics
// ---------------------------------------------------------------------------------------------------------

export type MetricKind = 'counter' | 'histogram';

/**
 * Label names a METRIC may carry. Deliberately much narrower than `isLoggableKey`.
 *
 * WHY A SECOND, STRICTER ALLOWLIST. The registry previously filtered labels with the log allowlist,
 * which permits any `*_id` suffix — correct for a log line, wrong for a metric. A metric label becomes a
 * distinct TIME SERIES, so `workspace_id` or `job_id` as a label is two defects at once: unbounded
 * cardinality that degrades the scraper, and a tenant identifier published on an endpoint that is
 * deliberately unauthenticated. Every name below is a closed enum or a bounded dimension; no identifier,
 * no hash, no free text, and nothing derived from user input.
 */
const ALLOWED_METRIC_LABELS: readonly string[] = [
  'activity',
  'backend',
  'check',
  'code',
  'component',
  'control',
  'dimension',
  'format',
  'kind',
  'method',
  'mode',
  'model_class',
  'operation_class',
  'outcome',
  'phase',
  'provider',
  'purpose',
  'reason',
  'result',
  'role',
  'route',
  'scope',
  'scope_kind',
  'source',
  'stage',
  'state',
  'status',
  'status_class',
  'step',
  'target_kind',
  'verb',
];

/** Whether a name may be a metric LABEL. Strict allowlist: an unknown name is not a label. */
export function isMetricLabel(key: string): boolean {
  return ALLOWED_METRIC_LABELS.includes(normalizeKey(key));
}

/**
 * Values a label may take, bounded per label name.
 *
 * A closed name is not enough on its own: `reason` is a safe NAME, but an arbitrary exception string as
 * its value would still be unbounded cardinality and a leak channel (a database error carries table and
 * column names; a provider error can carry a URL). So a value outside the known set collapses to
 * `other`, which keeps the series bounded and the signal honest.
 */
/**
 * A route PATTERN (`/v1/projects/:projectId`) is a bounded value and must stay readable, so a leading
 * slash and `:` placeholders are permitted. A resolved path is never passed here — that is the call
 * site's responsibility and the reason tenant ids cannot become label values.
 */
const LABEL_VALUE_PATTERN = /^[a-z0-9/][a-z0-9_.:/-]{0,63}$/;

export const METRIC_LABEL_OTHER = 'other';

export function safeLabelValue(value: string): string {
  // The VALUE is preserved as written when it is bounded and safe, rather than case-folded: an existing
  // enum like `UNAUTHENTICATED` is already a closed value, and rewriting it would silently rename series
  // that dashboards and the current tests refer to. The check is what matters, not the transformation.
  return LABEL_VALUE_PATTERN.test(value.toLowerCase()) ? value : METRIC_LABEL_OTHER;
}

interface MetricSeries {
  readonly kind: MetricKind;
  readonly help: string;
  /** Counter total, or histogram sum, keyed by serialized labels. */
  readonly values: Map<string, { sum: number; count: number; buckets: Map<number, number> }>;
}

/** Latency buckets in seconds, matching the plan's `llm_latency_seconds` histogram intent. */
const BUCKETS: readonly number[] = [0.01, 0.05, 0.1, 0.5, 1, 5, 30, 300];

/**
 * An in-process metric registry.
 *
 * Scope is stated plainly because it is a real limitation, not an implementation detail: these are
 * per-process counters. They reset on restart and are per-instance, so a multi-instance deployment needs a
 * scraper that aggregates across instances (which is how Prometheus works anyway). Nothing here claims to
 * be a distributed counter.
 */
export class Metrics {
  private readonly series = new Map<string, MetricSeries>();

  /** Register (idempotently) and return a series. */
  private seriesFor(name: string, kind: MetricKind, help: string): MetricSeries {
    const existing = this.series.get(name);
    if (existing) return existing;
    const created: MetricSeries = { kind, help, values: new Map() };
    this.series.set(name, created);
    return created;
  }

  /**
   * Serialize labels deterministically.
   *
   * Label VALUES are passed through `safeValue` and bounded, because a label is rendered into the metrics
   * endpoint's text output: an unbounded value there is both a cardinality explosion and a leak channel.
   */
  private static labelKey(labels: Readonly<Record<string, string>>): string {
    const entries = Object.entries(labels)
      // The STRICT metric allowlist, not the log one: a metric label is a time series, so an `*_id`
      // would be both unbounded cardinality and a tenant identifier on an unauthenticated endpoint.
      .filter(([k]) => isMetricLabel(k))
      .map(([k, v]) => [k, safeLabelValue(v)] as const)
      .sort((a, b) => a[0].localeCompare(b[0]));
    return entries.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(',');
  }

  increment(
    name: string,
    help: string,
    labels: Readonly<Record<string, string>> = {},
    by = 1,
  ): void {
    const s = this.seriesFor(name, 'counter', help);
    const key = Metrics.labelKey(labels);
    const cur = s.values.get(key);
    s.values.set(key, {
      sum: (cur?.sum ?? 0) + by,
      count: (cur?.count ?? 0) + 1,
      buckets: cur?.buckets ?? new Map<number, number>(),
    });
  }

  observe(
    name: string,
    help: string,
    seconds: number,
    labels: Readonly<Record<string, string>> = {},
  ): void {
    const s = this.seriesFor(name, 'histogram', help);
    const key = Metrics.labelKey(labels);
    const cur = s.values.get(key);
    const buckets = new Map<number, number>(cur?.buckets ?? []);
    for (const b of BUCKETS) if (seconds <= b) buckets.set(b, (buckets.get(b) ?? 0) + 1);
    s.values.set(key, {
      sum: (cur?.sum ?? 0) + seconds,
      count: (cur?.count ?? 0) + 1,
      buckets,
    });
  }

  /** Read one counter total, for tests and for readiness reporting. */
  total(name: string, labels: Readonly<Record<string, string>> = {}): number {
    return this.series.get(name)?.values.get(Metrics.labelKey(labels))?.sum ?? 0;
  }

  /** Render Prometheus text format. Contains only metric names, safe labels and numbers. */
  render(): string {
    const lines: string[] = [];
    for (const [name, s] of [...this.series.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      lines.push(`# HELP ${name} ${s.help}`);
      lines.push(`# TYPE ${name} ${s.kind}`);
      for (const [key, v] of [...s.values.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
        const labelPart = key ? `{${key}}` : '';
        if (s.kind === 'counter') {
          lines.push(`${name}${labelPart} ${v.sum}`);
          continue;
        }
        for (const b of BUCKETS) {
          const inner = key ? `${key},le="${b}"` : `le="${b}"`;
          lines.push(`${name}_bucket{${inner}} ${v.buckets.get(b) ?? 0}`);
        }
        const infInner = key ? `${key},le="+Inf"` : 'le="+Inf"';
        lines.push(`${name}_bucket{${infInner}} ${v.count}`);
        lines.push(`${name}_sum${labelPart} ${v.sum}`);
        lines.push(`${name}_count${labelPart} ${v.count}`);
      }
    }
    return `${lines.join('\n')}\n`;
  }
}

/** The metric names this system records, named once so producers and dashboards cannot drift apart. */
export const METRIC = {
  requests: 'yeonjae_http_requests_total',
  requestLatency: 'yeonjae_http_request_duration_seconds',
  authFailures: 'yeonjae_auth_failures_total',
  rateLimited: 'yeonjae_rate_limited_total',
  canonCommits: 'yeonjae_canon_commits_total',
  leaseLoss: 'yeonjae_lease_loss_total',
  jobControl: 'yeonjae_job_control_total',
  sseConnections: 'yeonjae_sse_connections_total',
  sseReplays: 'yeonjae_sse_replayed_events_total',
  exports: 'yeonjae_exports_total',
  budgetBlocks: 'yeonjae_budget_blocks_total',
  providerAttempts: 'yeonjae_provider_attempts_total',
  corsDenied: 'yeonjae_cors_denied_total',
  /**
   * Shared-enforcement, retrieval and recovery signals (Phase 4 automated readiness).
   *
   * Named here rather than at each call site so producers, dashboards and alert rules cannot drift
   * apart — the alert templates under `ops/` are validated against this object.
   */
  rateAdmission: 'yeonjae_rate_admission_total',
  rateWaitSeconds: 'yeonjae_rate_admission_wait_seconds',
  concurrencyAcquired: 'yeonjae_concurrency_acquired_total',
  concurrencySaturated: 'yeonjae_concurrency_saturated_total',
  leaseExpired: 'yeonjae_lease_expired_total',
  budgetReservations: 'yeonjae_budget_reservations_total',
  budgetSettlements: 'yeonjae_budget_settlements_total',
  reservationExpired: 'yeonjae_budget_reservations_expired_total',
  unknownCost: 'yeonjae_unknown_cost_settlements_total',
  retries: 'yeonjae_provider_retries_total',
  repairs: 'yeonjae_provider_repairs_total',
  fallbacks: 'yeonjae_provider_fallbacks_total',
  cancellationRequests: 'yeonjae_cancellation_requests_total',
  cancellationObservations: 'yeonjae_cancellation_observations_total',
  remoteCancellation: 'yeonjae_remote_cancellation_total',
  lateResponses: 'yeonjae_late_responses_total',
  discardedArtifacts: 'yeonjae_discarded_artifacts_total',
  staleWorkerRejections: 'yeonjae_stale_worker_rejections_total',
  workflowStates: 'yeonjae_workflow_state_transitions_total',
  activityAttempts: 'yeonjae_activity_attempts_total',
  queueDepth: 'yeonjae_queue_depth',
  dbPoolSaturation: 'yeonjae_db_pool_saturation_total',
  readinessFailures: 'yeonjae_readiness_failures_total',
  migrationMismatch: 'yeonjae_migration_mismatch_total',
  roleAssumptionFailures: 'yeonjae_role_assumption_failures_total',
  embeddingsGenerated: 'yeonjae_embeddings_generated_total',
  embeddingSetActivations: 'yeonjae_embedding_set_activations_total',
  retrievalLatency: 'yeonjae_retrieval_duration_seconds',
  retrievalResults: 'yeonjae_retrieval_results_total',
  thesaurusExpansions: 'yeonjae_thesaurus_expansions_total',
  backupOutcomes: 'yeonjae_backup_outcomes_total',
  restoreOutcomes: 'yeonjae_restore_outcomes_total',
  credentialRotations: 'yeonjae_credential_rotations_total',
} as const;

export const METRIC_HELP: Readonly<Record<string, string>> = {
  [METRIC.requests]: 'HTTP requests by route, method and status class.',
  [METRIC.requestLatency]: 'HTTP request duration in seconds by route.',
  [METRIC.authFailures]: 'Authentication and authorization failures by code.',
  [METRIC.rateLimited]: 'Requests refused by a rate limit, by scope.',
  [METRIC.canonCommits]: 'Canon commits by source.',
  [METRIC.leaseLoss]: 'Lease-loss refusals by reason.',
  [METRIC.jobControl]: 'Job control requests by control and outcome.',
  [METRIC.sseConnections]: 'SSE job-event streams opened.',
  [METRIC.sseReplays]: 'Job events replayed from a Last-Event-ID.',
  [METRIC.exports]: 'Export requests by format and status.',
  [METRIC.budgetBlocks]: 'Calls refused by the budget guard.',
  [METRIC.providerAttempts]: 'Provider attempts by model class and status.',
  [METRIC.corsDenied]: 'Cross-origin requests refused by the origin allowlist.',
  [METRIC.rateAdmission]: 'Shared rate-admission decisions by operation class and reason.',
  [METRIC.rateWaitSeconds]: 'Time a caller waited for shared rate admission, in seconds.',
  [METRIC.concurrencyAcquired]: 'Shared concurrency leases acquired by provider.',
  [METRIC.concurrencySaturated]: 'Attempts refused because shared concurrency was exhausted.',
  [METRIC.leaseExpired]: 'Leases reclaimed by deadline rather than released by their holder.',
  [METRIC.budgetReservations]: 'Shared budget reservations by scope kind and outcome.',
  [METRIC.budgetSettlements]: 'Shared budget settlements by scope kind and outcome.',
  [METRIC.reservationExpired]: 'Budget reservations reclaimed after their TTL.',
  [METRIC.unknownCost]: 'Settlements whose real cost the provider never reported.',
  [METRIC.retries]: 'Provider attempts retried, by failure class.',
  [METRIC.repairs]: 'Bounded structured-output repair attempts.',
  [METRIC.fallbacks]: 'Route fallbacks by reason.',
  [METRIC.cancellationRequests]: 'Cancellation requests by source.',
  [METRIC.cancellationObservations]: 'Cancellations observed by a running call, by phase.',
  [METRIC.remoteCancellation]: 'Remote cancellation states reported by a provider.',
  [METRIC.lateResponses]: 'Provider responses that arrived after an authoritative cancellation.',
  [METRIC.discardedArtifacts]: 'Artifacts discarded rather than committed, by reason.',
  [METRIC.staleWorkerRejections]: 'Writes refused because the worker held a stale fencing token.',
  [METRIC.workflowStates]: 'Workflow state transitions by state.',
  [METRIC.activityAttempts]: 'Activity attempts by activity and outcome.',
  [METRIC.queueDepth]: 'Work items waiting, by kind.',
  [METRIC.dbPoolSaturation]: 'Occasions a database pool had no connection available.',
  [METRIC.readinessFailures]: 'Readiness check failures by check name.',
  [METRIC.migrationMismatch]: 'Readiness refusals caused by a migration-state mismatch.',
  [METRIC.roleAssumptionFailures]: 'Failures to assume the expected least-privilege database role.',
  [METRIC.embeddingsGenerated]: 'Embeddings generated by backend and outcome.',
  [METRIC.embeddingSetActivations]: 'Embedding-set activations and rollbacks by outcome.',
  [METRIC.retrievalLatency]: 'Retrieval duration in seconds by mode.',
  [METRIC.retrievalResults]: 'Retrieval result counts by mode.',
  [METRIC.thesaurusExpansions]: 'Query-term expansions produced by the thesaurus, by kind.',
  [METRIC.backupOutcomes]: 'Local backup attempts by outcome.',
  [METRIC.restoreOutcomes]: 'Local restore drills by outcome.',
  [METRIC.credentialRotations]: 'Credential rotation events by kind and outcome.',
};
