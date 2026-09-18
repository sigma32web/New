/**
 * The durable orchestration worker entry point (Checkpoint 7).
 *
 * `YEONJAE_PROVIDER_MODE` decides how model calls are routed and there is deliberately no default that
 * reaches a paid provider: an unset mode is a startup error, not an implicit "go live". That is the same
 * rule the gateway already enforces for the CLI (no silent live calls), stated at the process boundary so
 * a misconfigured deployment fails before it can spend anything.
 */
import { NativeConnection, Worker } from '@temporalio/worker';
import { createActivities, poolFromEnv } from './activities.js';
import { CHAPTER_TASK_QUEUE } from './contracts.js';
import {
  assertSharedEnforcementAvailable,
  enforcementModeFromEnv,
  productionDeps,
} from './deps.js';

async function main(): Promise<void> {
  // Validate configuration BEFORE opening any connection. Connecting first meant a worker with no
  // provider mode failed with a Temporal transport error, which names the wrong problem entirely — and in
  // an environment where Temporal happened to be reachable it would have proceeded to build a gateway
  // from unvalidated configuration.
  const pool = poolFromEnv();
  const enforcement = enforcementModeFromEnv();
  /**
   * Fail closed when shared enforcement is required but unavailable.
   *
   * Checked before the Temporal connection, for the same reason the provider mode is: a worker that
   * cannot enforce a shared budget must not accept work at all, and discovering that after it has taken
   * a task would mean the first refusal is a spent call rather than a startup error.
   */
  if (enforcement === 'shared') await assertSharedEnforcementAvailable(pool);
  const makeDeps = productionDeps(pool, { enforcement });

  const address = process.env.TEMPORAL_ADDRESS ?? '127.0.0.1:7233';
  const namespace = process.env.TEMPORAL_NAMESPACE ?? 'default';
  const connection = await NativeConnection.connect({ address });

  const worker = await Worker.create({
    connection,
    namespace,
    taskQueue: process.env.TEMPORAL_TASK_QUEUE ?? CHAPTER_TASK_QUEUE,
    workflowsPath: new URL('./workflows.js', import.meta.url).pathname,
    activities: createActivities({ pool, makeDeps }),
  });

  const shutdown = (): void => {
    worker.shutdown();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  try {
    await worker.run();
  } finally {
    // Drain in a `finally` so a crashing worker still closes its Temporal connection and its pool.
    // Leaking either keeps the process alive and, for the pool, holds shared database connections
    // that the rest of the deployment needs.
    await connection.close();
    await pool.end();
  }
}

await main();
