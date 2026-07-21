# Email Trigram Index INSERT Benchmark

## Outcome

The partial `gin_trgm_ops` index reduced median paired INSERT throughput by 1.96% in this local benchmark. Across three trials, the measured change ranged from -0.68% to -4.20%. This is a small, single-digit write cost and passes the rollout gate for support-admin email search.

Both timed configurations started with 400,000 rows, approximating a mature production-sized index, and inserted another 40,000 rows. The earlier -3.11% result is superseded because it measured the timed GIN workload against an empty index. On the resulting 440,000-row dataset, PostgreSQL selected `idx_users_email_trgm` for both `ILIKE '%fragment%'` and the trigram similarity (`%`) operator. The median index size was 24,805,376 bytes (23.7 MiB).

The exact two-index migration sequence took 1,903 ms on a fresh 400,000-row clone in a July 20 follow-up run. Ordinary `CREATE INDEX` takes a lock that blocks writes for the build, and SQLx runs each migration transactionally, so this local duration is a lower bound for the production write-blocking window rather than a production latency prediction.

## Method

[`tools/benchmark-email-trgm-inserts.sh`](../tools/benchmark-email-trgm-inserts.sh) creates an isolated `email_trgm_benchmark` schema and never writes to application rows. It:

1. Clones `public.users` with `LIKE ... INCLUDING ALL`, preserving the users table's constraints and baseline indexes.
2. Removes both cloned migration indexes, recreates only the btree baseline, preloads 400,000 rows, and runs 40,000 single-row INSERT transactions through `pgbench`.
3. Truncates the clone, preloads the same 400,000 rows, drops the baseline btree index, and times the migration's GIN and btree index builds together.
4. Repeats the same 40,000 INSERT transactions with both migration indexes present.
5. Runs `ANALYZE` on the resulting 440,000-row indexed clone and captures `EXPLAIN (ANALYZE, BUFFERS)` for substring and similarity searches.
6. Drops the isolated schema on exit.

Each generated pubkey is a full 64-character value. One in 10,000 emails contains the plan-verification needle, yielding 44 matches in the 440,000-row dataset.

The corrected benchmark was run on July 19, 2026 with PostgreSQL 16.14 in Docker 29.6.1 on Linux 7.1.3, using an AMD Ryzen AI Max+ 395 (32 logical CPUs) and 125 GiB RAM. PostgreSQL and the benchmark client shared the local machine; results are useful for relative comparison, not production capacity planning.

## Reproduce

With PostgreSQL client tools installed locally:

```bash
tools/benchmark-email-trgm-inserts.sh \
  --database-url postgres://postgres:password@localhost:5432/keycast_test \
  --clients 4 \
  --transactions 10000 \
  --baseline-rows 400000
```

The same script can use the PostgreSQL 16 image's matching `pgbench` binary:

```bash
docker run --rm --network host \
  -v "$PWD/tools:/tools:ro" \
  postgres:16 \
  /tools/benchmark-email-trgm-inserts.sh \
  --database-url postgres://postgres:password@localhost:5432/keycast_test \
  --clients 4 \
  --transactions 10000 \
  --baseline-rows 400000
```

The script refuses non-local database URLs.

## Deployment Behavior

Production uses the normal unattended Cloud Build path. After pushing the new image, `cloudbuild.yaml` executes the `keycast-migrate` Cloud Run Job with `--wait`; that job runs the image's `./keycast --migrate` entrypoint before the service deploy step. A migration error fails the build and prevents the new service revision from deploying. The job does not set custom `PGOPTIONS`, so the accepted rollout behavior is the default transactional SQLx migration rather than a separate manually timed migration command.

Read-only production inspection on July 20, 2026 confirmed PostgreSQL 16, `pg_trgm` 1.6 available and trusted but not yet installed, and 216,549 users, including 41,122 with email. The migration role used by `keycast-migrate` inherits `cloudsqlsuperuser` and has `CREATE` on both the database and `public` schema, so it can run `CREATE EXTENSION IF NOT EXISTS pg_trgm` as part of the automated job. The email-bearing row count is well below the 400,000-row benchmark.

Non-production GKE deployments use the same binary migration path through the `keycast-db-migrate` ArgoCD sync-hook Job before the application Deployment. Database bootstrap assigns ownership and `public` schema privileges to the migration role, and a failed migration prevents the later Deployment sync wave. No separate live staging query is a release gate for this migration.

Both index statements are non-concurrent and block writes while their transaction remains open. `CREATE INDEX CONCURRENTLY` is not a drop-in replacement because PostgreSQL forbids it inside the transaction SQLx uses for a migration. The measured 1,903 ms local build is therefore a lower bound, not a production latency guarantee; monitor the migration job, write latency/errors, database CPU and I/O, and `pg_stat_activity` during rollout. Cancelling a migration that exceeds the acceptable window rolls back the transaction so it can be retried.

Re-run the 400,000-row benchmark if the target grows beyond 400,000 email-bearing users or the table/index layout changes materially.

## INSERT Results

Each configuration inserted 40,000 rows with four clients and 10,000 transactions per client.

| Trial | Without GIN latency | Without GIN TPS | With GIN latency | With GIN TPS | Paired TPS change |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.171 ms | 3,414.88 | 1.195 ms | 3,347.99 | -1.96% |
| 2 | 1.158 ms | 3,454.65 | 1.209 ms | 3,309.39 | -4.20% |
| 3 | 1.172 ms | 3,413.90 | 1.180 ms | 3,390.56 | -0.68% |
| Median | 1.171 ms | 3,414.88 | 1.195 ms | 3,347.99 | -1.96% paired |

The median latency increase was 0.024 ms. Median TPS values are shown independently; the rollout percentage uses the median of the three paired trial changes so host-speed drift between trials does not distort the comparison.

## Index Plan Verification

Representative substring plan (trial 1):

```text
Bitmap Heap Scan on users (actual time=1.425..1.530 rows=44 loops=1)
  Recheck Cond: (email ~~* '%needle-fragment%'::text)
  -> Bitmap Index Scan on idx_users_email_trgm
       Index Cond: (email ~~* '%needle-fragment%'::text)
Execution Time: 1.561 ms
```

Representative ranked-similarity plan (trial 1):

```text
Limit (actual time=4.137..4.138 rows=5 loops=1)
  -> Sort
       Sort Key: similarity(email, 'needle-fragment@rare.test'::text) DESC
       -> Bitmap Heap Scan on users
            Recheck Cond: (email % 'needle-fragment@rare.test'::text)
            -> Bitmap Index Scan on idx_users_email_trgm
                 Index Cond: (email % 'needle-fragment@rare.test'::text)
Execution Time: 4.151 ms
```

Both are cost-based plans; the benchmark does not disable sequential scans. Production hardware, cache state, row width, and write concurrency will change absolute values, so the script should be rerun after material schema or workload changes.
