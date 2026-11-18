/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { execSync, spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const ROOT = path.resolve(__dirname, "../..");
const CLI = path.join(ROOT, "dist", "index.js");
const FIXTURES = path.join(__dirname, "fixtures");
function createExpressDiffRepo(): { repoRoot: string; patchFile: string } {
    const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-diff-auto-"));
    fs.writeFileSync(path.join(repoRoot, ".arcconfig"), "{}\n");

    const projectDir = path.join(repoRoot, "server");
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(
        path.join(projectDir, "package.json"),
        JSON.stringify({ name: "server", dependencies: { express: "latest" } }),
    );
    fs.writeFileSync(
        path.join(projectDir, "tsconfig.json"),
        JSON.stringify({
            compilerOptions: {
                target: "es2020",
                module: "commonjs",
                esModuleInterop: true,
                skipLibCheck: true,
            },
            include: ["*.ts"],
        }),
    );
    fs.writeFileSync(
        path.join(projectDir, "server.ts"),
        `import express from "express";
import { exec } from "child_process";

const app = express();
app.post("/run", (req: any, res: any) => {
    exec(req.body.command);
    res.send("ok");
});
`,
    );

    const patchFile = path.join(repoRoot, "change.patch");
    fs.writeFileSync(patchFile, "diff --git a/server/server.ts b/server/server.ts\n");
    return { repoRoot, patchFile };
}

function runCli(
    args: string,
    envOverrides?: Record<string, string>,
    cwd: string = ROOT,
): {
    stdout: string;
    stderr: string;
    exitCode: number;
} {
    // spawnSync rather than execSync so we get stdout AND stderr back
    // regardless of exit code. execSync only returns stderr on the
    // exception path (non-zero exit), so stderr-capturing assertions
    // silently see "" whenever the CLI succeeds.
    const result = spawnSync("node", [CLI, ...args.split(/\s+/).filter(Boolean)], {
        cwd,
        encoding: "utf-8",
        timeout: 30_000,
        env: {
            ...process.env,
            ...envOverrides,
        },
    });
    return {
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        exitCode: result.status ?? 1,
    };
}

beforeAll(() => {
    execSync("./node_modules/.bin/tsc", { cwd: ROOT, timeout: 60_000 });
}, 60_000);

describe("CLI smoke tests", () => {
    it.each([
        "--shard-count 0",
        "--shard-count 1.5",
        "--shard-count NaN",
        "--shard-count Infinity",
        "--shard-count 2 --shard-index 2",
        "--shard-count 2 --shard-index -1",
        "--shard-count 2 --shard-index 0.5",
        "--max-depth -1",
        "--max-depth 1.5",
        "--max-depth NaN",
        "--max-depth Infinity",
        "--max-depth wrong",
    ])("rejects invalid numeric arguments: %s", (flags) => {
        const result = runCli(`--project ${FIXTURES}/uri-handler-rce --format json ${flags}`);
        expect(result.exitCode).toBe(1);
        expect(result.stdout).toBe("");
        expect(result.stderr).toContain("must be");
    });

    it.each(["0", "1"])("rejects resolved config failures with PROPHECY_NO_WORKER=%s", (noWorker) => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-cli-config-"));
        const sourceDirectory = path.join(directory, "src");
        fs.mkdirSync(sourceDirectory);
        fs.writeFileSync(path.join(sourceDirectory, "main.ts"), "export function main() {}\n");
        const config = path.join(directory, "tsconfig.json");
        const patch = path.join(directory, "change.patch");
        fs.writeFileSync(patch, "--- a/src/main.ts\n+++ b/src/main.ts\n");
        try {
            fs.writeFileSync(config, "{ invalid json !!!");
            for (const mode of [`--project ${sourceDirectory}`, `--patch-file ${patch} --repo-root ${directory}`]) {
                const result = runCli(`${mode} --format json`, { PROPHECY_NO_WORKER: noWorker });
                expect(result.exitCode).toBe(1);
                expect(result.stdout).toBe("");
                expect(result.stderr).toContain("failed to parse tsconfig.json");
            }
            for (const invalidConfig of [{ extends: "./missing.json" }, { files: ["missing.ts"] }]) {
                fs.writeFileSync(config, JSON.stringify(invalidConfig));
                const result = runCli(`--project ${directory} --require-types --format json`, {
                    PROPHECY_NO_WORKER: noWorker,
                });
                expect(result.exitCode).toBe(1);
                expect(result.stdout).toBe("");
                expect(result.stderr).toContain("failed to load");
            }
            fs.writeFileSync(config, '{"include":["wrong/*.ts"]}');
            const empty = runCli(`--project ${directory} --require-types --format json`, {
                PROPHECY_NO_WORKER: noWorker,
            });
            expect(empty.exitCode).toBe(0);
            expect(JSON.parse(empty.stdout)).toEqual([]);
            expect(empty.stderr).toContain("WARNING: No inputs were found");
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("requires type declarations in patch mode and warns without the flag", () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-cli-types-"));
        const patch = path.join(directory, "change.patch");
        fs.writeFileSync(patch, "--- untyped-node-module-rce/extension.ts\n+++ untyped-node-module-rce/extension.ts\n");
        try {
            const args = `--patch-file ${patch} --repo-root ${FIXTURES}`;
            const required = runCli(`${args} --require-types --format json`);
            expect(required.exitCode).not.toBe(0);
            expect(required.stderr).toContain("Missing type declarations");
            const permissive = runCli(`${args} --format text`);
            expect(permissive.exitCode).toBe(0);
            expect(permissive.stderr).toContain("Missing type declarations");
            expect(permissive.stdout).toContain("Found 1 taint flow:\n  CRITICAL  rce  1\n");
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("names the custom spec instead of the unused preset", () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-cli-spec-"));
        const spec = path.join(directory, "spec.json");
        fs.writeFileSync(spec, JSON.stringify({ sources: [], sinks: [], sanitizers: [] }));
        try {
            const { stdout, exitCode } = runCli(`--project ${path.join(FIXTURES, "uri-handler-rce")} --spec ${spec}`);
            expect(exitCode).toBe(0);
            expect(stdout).toContain(`Using spec: ${spec}`);
            expect(stdout).not.toContain("Using preset");
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("merges completed bundles without analyzing a project", () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bundle-cli-"));
        try {
            const issue = JSON.stringify({ kind: "issue", features: ["prophecy-handle:one"] }) + "\n";
            fs.writeFileSync(path.join(directory, "issues_0.sapp"), issue);
            fs.writeFileSync(path.join(directory, "issues_1.sapp"), issue);
            const result = runCli(`--merge-sapp-bundle ${directory}`);
            expect(result.exitCode).toBe(0);
            expect(result.stdout).toContain("1 findings, 1 duplicate rows removed");
            expect(fs.readFileSync(path.join(directory, "issues_1.sapp"), "utf8")).toBe("");
            expect(runCli(`--merge-sapp-bundle ${directory} --project ${FIXTURES}/uri-handler-rce`).exitCode).toBe(1);
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("accepts tsconfig JSONC syntax", () => {
        const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-jsonc-"));
        fs.writeFileSync(
            path.join(projectDir, "package.json"),
            JSON.stringify({ name: "jsonc-project", main: "extension.ts" }),
        );
        fs.writeFileSync(
            path.join(projectDir, "tsconfig.json"),
            `{
              // TypeScript accepts JSONC here.
              "compilerOptions": {
                "target": "es2020",
                "module": "commonjs",
                "skipLibCheck": true,
              },
              "include": ["*.ts"],
            }`,
        );
        fs.writeFileSync(
            path.join(projectDir, "extension.ts"),
            `import * as vscode from "vscode";
             import { exec } from "child_process";
             export function activate() {
                 vscode.window.registerUriHandler({
                     handleUri(uri: vscode.Uri) {
                         exec(uri.query);
                     }
                 });
             }`,
        );

        const { stdout, stderr, exitCode } = runCli(`--project ${projectDir} --format json`);

        expect(exitCode).toBe(0);
        expect(stderr).not.toContain("failed to parse tsconfig.json");
        expect(JSON.parse(stdout)).toHaveLength(1);
    });

    it("does not reject semantic tsconfig diagnostics during preflight", () => {
        const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-tsconfig-"));
        fs.writeFileSync(
            path.join(projectDir, "tsconfig.json"),
            JSON.stringify({
                compilerOptions: {
                    target: "es2020",
                    definitelyUnknownCompilerOption: true,
                },
                include: ["*.ts"],
            }),
        );
        fs.writeFileSync(
            path.join(projectDir, "extension.ts"),
            `import * as vscode from "vscode";
             import { exec } from "child_process";
             export function activate() {
                 vscode.window.registerUriHandler({
                     handleUri(uri: vscode.Uri) {
                         exec(uri.query);
                     }
                 });
             }`,
        );

        const { stdout, stderr, exitCode } = runCli(`--project ${projectDir} --preset vscode-extension --format json`);

        expect(exitCode).toBe(0);
        expect(stderr).not.toContain("failed to parse tsconfig.json");
        expect(JSON.parse(stdout)).toHaveLength(1);
    });

    it.each(["0", "1"])("rejects a reference-only solution with PROPHECY_NO_WORKER=%s", (noWorker) => {
        const { stdout, stderr, exitCode } = runCli(
            `--project ${path.join(FIXTURES, "project-references-solution")} --require-types --format json`,
            { PROPHECY_NO_WORKER: noWorker },
        );
        expect(exitCode).toBe(2);
        expect(stdout.trim()).toBe("");
        expect(stderr).toContain("project references but no input files");
        expect(stderr).toContain("separate --project arguments");
    });

    it("does not write a partial SAPP bundle when another root is reference-only", () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-solution-output-"));
        const outputDir = path.join(directory, "bundle");
        const solution = path.join(FIXTURES, "project-references-solution");
        try {
            const result = runCli(
                `--project ${path.join(solution, "app")} --project ${solution} --require-types ` +
                    `--format sapp-json --output-dir ${outputDir}`,
            );
            expect(result.exitCode).toBe(2);
            expect(result.stdout.trim()).toBe("");
            expect(result.stderr).toContain("project references but no input files");
            expect(fs.existsSync(outputDir)).toBe(false);
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("scans a referenced project directly with required declarations", () => {
        const { stdout, exitCode } = runCli(
            `--project ${path.join(FIXTURES, "project-references-solution", "app")} --require-types --format json`,
        );
        expect(exitCode).toBe(0);
        expect(JSON.parse(stdout)).toHaveLength(1);
    });

    it("reports TypeScript parser diagnostics for malformed tsconfig", () => {
        const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-bad-jsonc-"));
        fs.writeFileSync(path.join(projectDir, "extension.ts"), "export function main() {}\n");
        fs.writeFileSync(path.join(projectDir, "tsconfig.json"), "{ this is not valid json !!!\n");

        const { stderr, exitCode } = runCli(`--project ${projectDir} --format json`);

        expect(exitCode).toBe(1);
        expect(stderr).toContain("Error: failed to parse tsconfig.json");
        expect(stderr).toMatch(/tsconfig\.json:\d+:\d+:/);
    });

    it("exits 0 and reports CRITICAL for vulnerable fixture", () => {
        const { stdout, exitCode } = runCli(`--project ${path.join(FIXTURES, "uri-handler-rce")}`);
        expect(exitCode).toBe(0);
        expect(stdout).toContain("CRITICAL");
        expect(stdout).toContain("exec");
    });

    it("prints analysis stats when requested", () => {
        const { stdout, exitCode } = runCli(`--project ${path.join(FIXTURES, "uri-handler-rce")} --analysis-stats`);
        expect(exitCode).toBe(0);
        expect(stdout).toContain("Analysis metrics:");
        expect(stdout).toContain("Interprocedural cache hits:");
        expect(stdout).toContain("Type resolution attempts:");
        expect(stdout).toContain("Heuristic fallback attempts:");
        expect(stdout).toContain("Heuristic-only source checks:");
        expect(stdout).not.toContain("Heuristic attempts:");
    });

    it("prints structured analysis debug data when requested", () => {
        const { stdout, exitCode } = runCli(`--project ${path.join(FIXTURES, "uri-handler-rce")} --analysis-debug`);
        expect(exitCode).toBe(0);
        expect(stdout).toContain("Analysis debug log:");
        expect(stdout).toContain('"summary"');
        expect(stdout).toContain('"patternMatching"');
        expect(stdout).toContain('"counts"');
        expect(stdout).toContain('"entries"');
        expect(stdout).toContain('"strategy": "typeResolved"');
    });

    it("writes analysis debug data to stderr for JSON output", () => {
        const { stdout, stderr, exitCode } = runCli(
            `--project ${path.join(FIXTURES, "uri-handler-rce")} --format json --analysis-debug`,
        );
        expect(exitCode).toBe(0);
        expect(JSON.parse(stdout).length).toBeGreaterThanOrEqual(1);
        expect(stderr).toContain("Analysis debug log:");
        expect(stderr).toContain('"patternMatching"');
    });

    it("emits one JSON array for multiple project roots", () => {
        const { stdout, exitCode } = runCli(
            `--project ${path.join(FIXTURES, "uri-handler-rce")} --project ${path.join(FIXTURES, "exec-injection")} --format json`,
        );

        expect(exitCode).toBe(0);
        const findings = JSON.parse(stdout);
        expect(findings.length).toBe(2);
        expect(findings.map((finding: any) => finding.sink.name)).toEqual(["exec", "exec"]);
    });

    it("exits 0 and reports no findings for safe fixture", () => {
        const { stdout, exitCode } = runCli(`--project ${path.join(FIXTURES, "sanitized-input")}`);
        expect(exitCode).toBe(0);
        expect(stdout).toContain("No taint flows detected");
    });

    it("resolves repo-relative project paths when run from subdirectories", () => {
        // The project path is intentionally not relative to the cwd. It should
        // resolve against the nearest .arcconfig root after the cwd check fails.
        const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-repo-"));
        fs.writeFileSync(path.join(repoRoot, ".arcconfig"), "{}\n");
        fs.cpSync(path.join(FIXTURES, "uri-handler-rce"), path.join(repoRoot, "extensions", "uri-handler-rce"), {
            recursive: true,
        });
        const cwd = path.join(repoRoot, "tools");
        fs.mkdirSync(cwd);
        const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-sapp-"));
        const { exitCode } = runCli(
            `--project extensions/uri-handler-rce --format sapp-json --output-dir ${outputDir} --sapp-project vscode`,
            undefined,
            cwd,
        );

        expect(exitCode).toBe(0);
        const runnerMetadata = JSON.parse(fs.readFileSync(path.join(outputDir, "runner_metadata.json"), "utf-8"));
        expect(runnerMetadata.project).toBe("vscode");
    });

    it("writes SAPP bundle files for sapp-json output", () => {
        const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-sapp-"));
        const { stdout, exitCode } = runCli(
            `--project ${path.join(FIXTURES, "uri-handler-rce")} --format sapp-json --output-dir ${outputDir}`,
        );

        expect(exitCode).toBe(0);
        expect(fs.readdirSync(outputDir).sort()).toEqual([
            "issues_1.sapp",
            "runner_metadata.json",
            "sapper_metadata.json",
            "traceFrames_1.sapp",
        ]);

        const runnerMetadata = JSON.parse(fs.readFileSync(path.join(outputDir, "runner_metadata.json"), "utf-8"));
        expect(runnerMetadata).toMatchObject({
            root: "N/A",
            project: "uri-handler-rce",
        });
        expect(runnerMetadata.version).toBe("unknown");

        const sapperMetadata = JSON.parse(fs.readFileSync(path.join(outputDir, "sapper_metadata.json"), "utf-8"));
        expect(sapperMetadata.tool).toBe("prophecy");
        expect(sapperMetadata.filename_glob).toBe("*.sapp");
        expect(sapperMetadata.rules.length).toBeGreaterThanOrEqual(9);

        const issues = fs
            .readFileSync(path.join(outputDir, "issues_1.sapp"), "utf-8")
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
        expect(issues.length).toBeGreaterThanOrEqual(1);
        expect(
            issues.every((issue: any) =>
                issue.traces.every((trace: any) => (trace.forward ?? trace.backward).call.port === "prophecy"),
            ),
        ).toBe(true);
        const traceFrames = fs
            .readFileSync(path.join(outputDir, "traceFrames_1.sapp"), "utf-8")
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
        expect(traceFrames.length).toBeGreaterThanOrEqual(2);
        expect(traceFrames.every((frame: any) => frame.caller_port === "prophecy")).toBe(true);
        const nonLeafTraceFrames = traceFrames.filter(
            (frame: any) => frame.callee_port !== "source" && frame.callee_port !== "sink",
        );
        expect(nonLeafTraceFrames.every((frame: any) => frame.callee_port === "prophecy")).toBe(true);
        expect(traceFrames.some((frame: any) => frame.callee_port === "source")).toBe(true);
        expect(traceFrames.some((frame: any) => frame.callee_port === "sink")).toBe(true);
        expect(traceFrames.some((frame: any) => frame.type === "postcondition")).toBe(true);
        expect(traceFrames.some((frame: any) => frame.type === "precondition")).toBe(true);
        expect(stdout).toContain("runner_metadata.json");
        expect(stdout).toContain("sapper_metadata.json");
        expect(stdout).toContain("issues_1.sapp");
        expect(stdout).toContain("traceFrames_1.sapp");
    });

    it("uses --sapp-project for SAPP runner metadata", () => {
        const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-sapp-"));
        const { exitCode } = runCli(
            `--project ${path.join(FIXTURES, "uri-handler-rce")} --format sapp-json --output-dir ${outputDir} --sapp-project vscode`,
        );

        expect(exitCode).toBe(0);
        const runnerMetadata = JSON.parse(fs.readFileSync(path.join(outputDir, "runner_metadata.json"), "utf-8"));
        expect(runnerMetadata.project).toBe("vscode");
    });

    it("uses --sapp-commit for SAPP runner metadata", () => {
        const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-sapp-"));
        const commit = "0123456789abcdef0123456789abcdef01234567";
        const { exitCode } = runCli(
            `--project ${path.join(FIXTURES, "uri-handler-rce")} --format sapp-json --output-dir ${outputDir} --sapp-commit ${commit}`,
        );

        expect(exitCode).toBe(0);
        const runnerMetadata = JSON.parse(fs.readFileSync(path.join(outputDir, "runner_metadata.json"), "utf-8"));
        expect(runnerMetadata.commit).toBe(commit);
    });

    it("fails with error when --project is missing", () => {
        const { stdout, stderr, exitCode } = runCli("");
        expect(exitCode).not.toBe(0);
        const output = stdout + stderr;
        expect(output).toContain("exactly one of --project, --diff, --patch-file, or --merge-sapp-bundle is required");
    });

    it("uses auto preset for diff lint output", () => {
        const { repoRoot, patchFile } = createExpressDiffRepo();

        const { stdout, stderr, exitCode } = runCli(`--patch-file ${patchFile} --repo-root ${repoRoot} --format lint`);

        expect(exitCode).toBe(0);
        expect(stderr).not.toContain("Cannot read");
        const messages = stdout
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
        expect(messages.some((message: any) => message.code === "PROPHECY-RCE")).toBe(true);
    });

    it("uses auto preset for diff SAPP output", () => {
        const { repoRoot, patchFile } = createExpressDiffRepo();
        const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-sapp-"));

        const { exitCode } = runCli(
            `--patch-file ${patchFile} --repo-root ${repoRoot} --format sapp-json --output-dir ${outputDir}`,
        );

        expect(exitCode).toBe(0);
        const issues = fs
            .readFileSync(path.join(outputDir, "issues_1.sapp"), "utf-8")
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
        expect(issues.some((issue: any) => issue.code === 9001)).toBe(true);
    });
});
