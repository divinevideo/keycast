# Email Trigram Index INSERT Benchmark

## Outcome

The partial `gin_trgm_ops` index reduced median paired INSERT throughput by 3.11% in this local benchmark. Across three trials, the measured change ranged from -2.67% to -4.69%. This is a small, single-digit write cost and passes the rollout gate for support-admin email search.

On the 400,000-row plan-verification dataset, PostgreSQL selected `idx_users_email_trgm` for both `ILIKE '%fragment%'` and the trigram similarity (`%`) operator. The median index size was 23,724,032 bytes (22.6 MiB).

## Method

[`tools/benchmark-email-trgm-inserts.sh`](../tools/benchmark-email-trgm-inserts.sh) creates an isolated `email_trgm_benchmark` schema and never writes to application rows. It:

1. Clones `public.users` with `LIKE ... INCLUDING ALL`, preserving the users table's constraints and baseline indexes.
2. Removes only the cloned `gin_trgm_ops` index and runs 40,000 single-row INSERT transactions through `pgbench`.
3. Truncates the clone, adds the partial GIN index, and repeats the same 40,000 INSERT transactions.
4. Populates the indexed clone to 400,000 rows, runs `ANALYZE`, and captures `EXPLAIN (ANALYZE, BUFFERS)` for substring and similarity searches.
5. Drops the isolated schema on exit.

Each generated pubkey is a full 64-character value. One in 10,000 emails contains the plan-verification needle, yielding 40 matches in the 400,000-row dataset.

The benchmark was run on July 17, 2026 with PostgreSQL 16.14 in Docker 29.6.1 on Linux 7.1.3, using an AMD Ryzen AI Max+ 395 (32 logical CPUs) and 125 GiB RAM. PostgreSQL and the benchmark client shared the local machine; results are useful for relative comparison, not production capacity planning.

## Reproduce

With PostgreSQL client tools installed locally:

```bash
tools/benchmark-email-trgm-inserts.sh \
  --database-url postgres://postgres:password@localhost:5432/keycast_test \
  --clients 4 \
  --transactions 10000 \
  --explain-rows 400000
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
  --explain-rows 400000
```

The script refuses non-local database URLs.

## INSERT Results

Each configuration inserted 40,000 rows with four clients and 10,000 transactions per client.

| Trial | Without GIN latency | Without GIN TPS | With GIN latency | With GIN TPS | Paired TPS change |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1.120 ms | 3,570.95 | 1.151 ms | 3,475.78 | -2.67% |
| 2 | 1.099 ms | 3,638.77 | 1.153 ms | 3,468.01 | -4.69% |
| 3 | 1.109 ms | 3,607.01 | 1.145 ms | 3,494.74 | -3.11% |
| Median | 1.109 ms | 3,607.01 | 1.151 ms | 3,475.78 | -3.11% paired |

The median latency increase was 0.042 ms. Median TPS values are shown independently; the rollout percentage uses the median of the three paired trial changes so host-speed drift between trials does not distort the comparison.

## Index Plan Verification

Representative substring plan (trial 1):

```text
Bitmap Heap Scan on users (actual time=2.795..2.907 rows=40 loops=1)
  Recheck Cond: (email ~~* '%needle-fragment%'::text)
  -> Bitmap Index Scan on idx_users_email_trgm
       Index Cond: (email ~~* '%needle-fragment%'::text)
Execution Time: 2.919 ms
```

Representative ranked-similarity plan (trial 1):

```text
Limit (actual time=6.117..6.117 rows=5 loops=1)
  -> Sort
       Sort Key: similarity(email, 'needle-fragment@rare.test'::text) DESC
       -> Bitmap Heap Scan on users
            Recheck Cond: (email % 'needle-fragment@rare.test'::text)
            -> Bitmap Index Scan on idx_users_email_trgm
                 Index Cond: (email % 'needle-fragment@rare.test'::text)
Execution Time: 6.130 ms
```

Both are cost-based plans; the benchmark does not disable sequential scans. The narrow synthetic table used for the 40,000-row INSERT comparison is too small for PostgreSQL to prefer the GIN index, which is why plan verification uses a separately reported 400,000-row population. Production hardware, cache state, row width, and write concurrency will change absolute values, so the script should be rerun after material schema or workload changes.
