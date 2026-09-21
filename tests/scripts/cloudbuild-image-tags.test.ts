import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";

type BuildConfig = {
  steps: { name: string; args?: string[] }[];
  images: string[];
};

const config = Bun.YAML.parse(
  readFileSync(new URL("../../cloudbuild.yaml", import.meta.url), "utf8"),
) as BuildConfig;

// Exercise the actual build/push/deploy arguments without contacting a registry
// or deploying. Registry values represent distinct outputs of separate builds,
// even when their source commit is identical (base images can change).
function runBuild(
  registry: Map<string, string>,
  commit: string,
  buildId: string,
) {
  const values: Record<string, string> = {
    PROJECT_ID: "test-project",
    COMMIT_SHA: commit,
    BUILD_ID: buildId,
  };
  const expand = (value: string) =>
    value.replace(/\$\{(PROJECT_ID|COMMIT_SHA|BUILD_ID)\}/g, (_, key) => values[key]);
  const localImages = new Map<string, string>();
  let deployedImage: string | undefined;

  for (const step of config.steps) {
    const args = (step.args ?? []).map(expand);
    if (step.name === "gcr.io/cloud-builders/docker") {
      if (args[0] === "build") {
        for (let index = 1; index < args.length; index++) {
          if (args[index] === "-t") localImages.set(args[++index], buildId);
        }
      } else if (args[0] === "push") {
        expect(localImages.has(args[1])).toBe(true);
        registry.set(args[1], localImages.get(args[1])!);
      } else {
        throw new Error(`Unsupported Docker operation: ${args[0]}`);
      }
    } else if (args.includes("deploy") && args.includes("keycast")) {
      deployedImage = args.find((arg) => arg.startsWith("--image="))?.slice(8);
      expect(deployedImage).toBeDefined();
      expect(registry.get(deployedImage!)).toBe(buildId);
    }
  }
  for (const image of config.images.map(expand)) {
    expect(localImages.has(image)).toBe(true);
    registry.set(image, localImages.get(image)!);
  }
  expect(deployedImage).toBeDefined();
  expect(deployedImage).toContain(commit);
  expect(deployedImage).not.toEndWith(":latest");
  return deployedImage!;
}

test("rebuilding a commit preserves the earlier deployment's rollback image", () => {
  const registry = new Map<string, string>();
  const commit = "a".repeat(40);
  const first = runBuild(registry, commit, "11111111-1111-4111-8111-111111111111");
  const second = runBuild(registry, commit, "22222222-2222-4222-8222-222222222222");

  expect(second).not.toBe(first);
  expect(registry.get(first)).toBe("11111111-1111-4111-8111-111111111111");
  expect(registry.get(second)).toBe("22222222-2222-4222-8222-222222222222");
  expect(registry.get("us-central1-docker.pkg.dev/test-project/docker/keycast:latest"))
    .toBe("22222222-2222-4222-8222-222222222222");
});

test("a newer commit does not move the earlier commit's rollback image", () => {
  const registry = new Map<string, string>();
  const first = runBuild(registry, "a".repeat(40), "11111111-1111-4111-8111-111111111111");
  runBuild(registry, "b".repeat(40), "22222222-2222-4222-8222-222222222222");
  expect(registry.get(first)).toBe("11111111-1111-4111-8111-111111111111");
});
