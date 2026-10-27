import { readFile, writeFile } from "node:fs/promises";

interface SummaryCase { id: string; passed: boolean }
interface Summary { schema_version: 1; cases: SummaryCase[] }
export interface SummaryIO { read(): Promise<string | undefined>; write(contents: string): Promise<void> }
const SUMMARY_PATH = "/tmp/challenge-image-summary.json";
const fileIO: SummaryIO = {
  async read() {
    try { return await readFile(SUMMARY_PATH, "utf8"); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
  },
  async write(contents) { await writeFile(SUMMARY_PATH, contents, { mode: 0o600 }); },
};
function check(value: unknown, category: string): asserts value {
  if (!value) throw new Error(`challenge_image:summary_${category}`);
}
const exactKeys = (value: unknown, keys: string[]): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

// Each run has its own runner-created client /tmp tmpfs. Workers are sequential
// but Playwright replaces a failed worker: load the file, never a module cache.
export function createSummaryRecorder(allowedIds: readonly string[], io: SummaryIO = fileIO) {
  const allowed = new Set(allowedIds);
  async function load(): Promise<Summary | undefined> {
    let raw: string | undefined;
    try { raw = await io.read(); } catch { throw new Error("challenge_image:summary_io"); }
    if (raw === undefined) return undefined;
    let value: unknown;
    try { value = JSON.parse(raw); } catch { throw new Error("challenge_image:summary_schema"); }
    check(exactKeys(value, ["schema_version", "cases"]) && value.schema_version === 1 && Array.isArray(value.cases), "schema");
    const seen = new Set<string>();
    for (const row of value.cases) {
      check(exactKeys(row, ["id", "passed"]) && typeof row.id === "string" && typeof row.passed === "boolean", "schema");
      check(allowed.has(row.id), "case");
      check(!seen.has(row.id), "duplicate"); seen.add(row.id);
    }
    return value as unknown as Summary;
  }
  async function save(value: Summary): Promise<void> {
    try { await io.write(JSON.stringify(value)); } catch { throw new Error("challenge_image:summary_io"); }
  }
  async function initialize(): Promise<void> {
    // Existing valid evidence is not rewritten or reset by beforeAll/afterAll.
    // Only an absent file needs the initial empty aggregate.
    const value = await load();
    if (value === undefined) await save({ schema_version: 1, cases: [] });
  }
  async function recordCase(id: string, operation: () => Promise<void>): Promise<void> {
    check(allowed.has(id), "case");
    const value = await load() ?? { schema_version: 1 as const, cases: [] };
    check(!value.cases.some(row => row.id === id), "duplicate");
    const row = { id, passed: false }; value.cases.push(row);
    // Persist an attempted failure before awaiting its body. Only this newly
    // appended row can become true; prior false entries cannot be upgraded.
    await save(value);
    try { await operation(); row.passed = true; }
    catch { throw new Error("challenge_image:case_failed"); }
    finally { await save(value); }
  }
  return { initialize, recordCase };
}
