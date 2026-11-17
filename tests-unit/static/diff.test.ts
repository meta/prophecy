/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { analyzeDiffScreening } from "../../src/static/diff";
import { parseUnifiedDiffPaths } from "../../src/static/sourceControl";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";

const FIXTURES = path.join(__dirname, "fixtures");
const DIFF_REPO_ROOT = path.join(FIXTURES, "diff-repos", "sample");

describe("patch project selection", () => {
    it("analyzes configless files alongside configured projects", async () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-configless-patch-"));
        const patchFile = path.join(directory, "change.patch");
        const source = `import * as vscode from "vscode";
            import { exec } from "child_process";
            export function activate() {
                vscode.window.registerUriHandler({handleUri(uri: vscode.Uri) {exec(uri.query);}});
            }`;
        try {
            for (const name of ["standalone", "configured"]) {
                fs.mkdirSync(path.join(directory, name));
                fs.writeFileSync(path.join(directory, name, "extension.ts"), source);
            }
            fs.writeFileSync(path.join(directory, "configured", "tsconfig.json"), '{"include":["*.ts"]}');
            fs.writeFileSync(
                patchFile,
                "--- a/configured/extension.ts\n+++ b/configured/extension.ts\n" +
                    "--- a/standalone/extension.ts\n+++ b/standalone/extension.ts\n",
            );
            const result = await analyzeDiffScreening({
                patchFile,
                repoRoot: directory,
                outputFormat: "json",
                spec: vscodeExtensionSpec,
            });
            expect(result.findings).toHaveLength(2);
            expect(
                result.findings.map((finding) => path.relative(directory, finding.sinkLocation.fileName)).sort(),
            ).toEqual(["configured/extension.ts", "standalone/extension.ts"]);
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it.each([
        ["missing.ts", "Changed TypeScript file does not exist"],
        ["../outside.ts", "Changed path is outside --repo-root"],
    ])("diagnoses unscannable changed paths: %s", async (changed, message) => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-invalid-patch-path-"));
        const patchFile = path.join(directory, "change.patch");
        fs.writeFileSync(patchFile, `--- a/${changed}\n+++ b/${changed}\n`);
        try {
            await expect(analyzeDiffScreening({ patchFile, repoRoot: directory })).rejects.toThrow(message);
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });
});

describe("diff helpers", () => {
    it("parses traditional unified headers, timestamps, and deletions", () => {
        expect(
            parseUnifiedDiffPaths(
                [
                    "--- server.ts\t2026-01-01 00:00:00",
                    "+++ server.ts\t2026-01-02 00:00:00",
                    "@@ -1 +1 @@",
                    "-old",
                    "+new",
                    "--- removed.ts",
                    "+++ /dev/null",
                    "@@ -1 +0,0 @@",
                    "-removed",
                ].join("\n"),
            ),
        ).toEqual(["server.ts"]);
    });

    it("decodes quoted Git paths and ignores header-shaped hunk contents", () => {
        expect(
            parseUnifiedDiffPaths(
                [
                    'diff --git "a/caf\\303\\251.ts" "b/caf\\303\\251.ts"',
                    '--- "a/caf\\303\\251.ts"',
                    '+++ "b/caf\\303\\251.ts"',
                    "@@ -1 +1 @@",
                    "--- fake.ts",
                    "+++ fake.ts",
                    "diff --git a/with spaces.ts b/with spaces.ts",
                ].join("\n"),
            ),
        ).toEqual(["café.ts", "with spaces.ts"]);
    });

    it.each(["not a patch", "diff --git invalid", "--- incomplete.ts", "--- a/x.ts\n+++ b/x.ts\n@@ -1 +1 @@\n-old"])(
        "rejects unsupported or truncated patches: %s",
        (patch) => {
            expect(() => parseUnifiedDiffPaths(patch)).toThrow();
        },
    );

    it.each(["\n", "\r\n"])("accepts blank context lines with line ending %j", (newline) => {
        expect(
            parseUnifiedDiffPaths(
                ["--- a/server.ts", "+++ b/server.ts", "@@ -1,4 +1,4 @@", " ", "", "-old", "+new", "", ""].join(
                    newline,
                ),
            ),
        ).toEqual(["server.ts"]);
    });

    it.each(["@@ -1 +1 @@\n", "@@ -1,2 +1,2 @@\n-old\n+new\n", "@@ -0,0 +1 @@\n\n"])(
        "does not fill missing hunk lines with a terminal newline: %s",
        (hunk) => {
            expect(() => parseUnifiedDiffPaths(`--- a/x.ts\n+++ b/x.ts\n${hunk}`)).toThrow();
        },
    );

    it("enforces required declarations and retains warnings in patch screening", async () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-patch-types-"));
        const patchFile = path.join(directory, "change.patch");
        fs.writeFileSync(
            patchFile,
            "--- untyped-node-module-rce/extension.ts\n+++ untyped-node-module-rce/extension.ts\n",
        );
        const options = { patchFile, repoRoot: FIXTURES, outputFormat: "json" as const };
        try {
            await expect(analyzeDiffScreening({ ...options, requireTypes: true })).rejects.toThrow(
                "Missing type declarations",
            );
            const result = await analyzeDiffScreening(options);
            expect(result.typeEnvironmentWarning).toContain("prophecy-missing-types");
            expect(result.findings).toHaveLength(1);
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("parses changed file paths from a unified diff", () => {
        const paths = parseUnifiedDiffPaths(`diff --git a/foo.ts b/foo.ts
diff --git a/bar/baz.tsx b/bar/baz.tsx
`);

        expect(paths).toEqual(["foo.ts", "bar/baz.tsx"]);
    });

    it("filters changed-file traces before choosing a same-handle representative", async () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-diff-traces-"));
        const patchFile = path.join(directory, "change.patch");
        fs.writeFileSync(
            path.join(directory, "tsconfig.json"),
            JSON.stringify({
                compilerOptions: {
                    module: "commonjs",
                    typeRoots: [path.join(__dirname, "../../node_modules/@types")],
                    types: ["node", "vscode"],
                },
                include: ["*.ts"],
            }),
        );
        fs.writeFileSync(
            path.join(directory, "changed.ts"),
            'import * as shlex from "shlex"; export function quotedCommand(value: string) { return `demo --name ${shlex.quote(value)}`; }',
        );
        fs.writeFileSync(
            path.join(directory, "extension.ts"),
            `import * as vscode from "vscode";
            import { quotedCommand } from "./changed";
            export function activate() {
                vscode.window.registerUriHandler({ handleUri(uri: vscode.Uri) {
                    let command;
                    if (uri.path) command = quotedCommand(uri.query);
                    else command = uri.fragment;
                    vscode.window.createTerminal("Device").sendText(command);
                }});
            }`,
        );
        fs.writeFileSync(patchFile, "--- a/changed.ts\n+++ b/changed.ts\n");
        try {
            const result = await analyzeDiffScreening({
                patchFile,
                repoRoot: directory,
                spec: vscodeExtensionSpec,
                outputFormat: "json",
            });
            expect(result.findings).toHaveLength(1);
            expect(result.findings[0].sink.categories).toEqual(["arg_injection"]);
            expect(
                result.findings[0].propagationChain.some((step) => step.location.fileName.endsWith("/changed.ts")),
            ).toBe(true);
        } finally {
            fs.rmSync(directory, { recursive: true, force: true });
        }
    });

    it("screens findings through the production diff path", async () => {
        const patchFile = path.join(os.tmpdir(), `prophecy-diff-${process.pid}.patch`);
        fs.writeFileSync(
            patchFile,
            `diff --git a/vscode-extensions/core/src/commands/runTerminalCommand.ts b/vscode-extensions/core/src/commands/runTerminalCommand.ts
`,
        );

        const result = await analyzeDiffScreening({
            patchFile,
            repoRoot: DIFF_REPO_ROOT,
            spec: vscodeExtensionSpec,
            outputFormat: "json",
        });

        expect(result.findings.length).toBe(1);
        expect(result.findings[0].sink.name).toBe("sendText");
    });
});
