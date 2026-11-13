/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { resolveFixStrategy } from "../../../src/static/fix/fixStrategy";
import { SinkSpec, FixStrategy } from "../../../src/static/spec/types";

function makeSink(name: string, categories: string[]): SinkSpec {
    return {
        kind: "callArgument",
        name,
        pattern: `test.${name}`,
        description: `Test sink: ${name}`,
        severity: "critical",
        categories: categories as any,
    };
}

describe("resolveFixStrategy", () => {
    it("resolves exec sink to execFile strategy", () => {
        const strategy = resolveFixStrategy(makeSink("exec", ["rce"]));
        expect(strategy).toBeDefined();
        expect(strategy!.saferAPI).toBe("child_process.execFile");
        expect(strategy!.applicability).toBe("unsafe");
    });

    it("resolves execSync sink to execFileSync strategy", () => {
        const strategy = resolveFixStrategy(makeSink("execSync", ["rce"]));
        expect(strategy).toBeDefined();
        expect(strategy!.saferAPI).toBe("child_process.execFileSync");
    });

    it("resolves sendText sink to shell-quote strategy", () => {
        const strategy = resolveFixStrategy(makeSink("sendText", ["rce"]));
        expect(strategy).toBeDefined();
        expect(strategy!.importPackage).toBe("shell-quote");
        expect(strategy!.importName).toBe("quote");
    });

    it("resolves ShellExecution to ProcessExecution strategy", () => {
        const strategy = resolveFixStrategy(makeSink("ShellExecution", ["rce"]));
        expect(strategy).toBeDefined();
        expect(strategy!.saferAPI).toBe("vscode.ProcessExecution");
        expect(strategy!.importPackage).toBe("vscode");
        expect(strategy!.importName).toBe("ProcessExecution");
    });

    it("marks eval as unfixable", () => {
        const strategy = resolveFixStrategy(makeSink("eval", ["code_injection"]));
        expect(strategy).toBeDefined();
        expect(strategy!.applicability).toBe("unfixable");
    });

    it("marks executeCommand as unfixable", () => {
        const strategy = resolveFixStrategy(makeSink("executeCommand", ["rce"]));
        expect(strategy).toBeDefined();
        expect(strategy!.applicability).toBe("unfixable");
    });

    it("marks ssrf as unfixable", () => {
        const strategy = resolveFixStrategy(makeSink("fetch", ["ssrf"]));
        expect(strategy).toBeDefined();
        expect(strategy!.applicability).toBe("unfixable");
    });

    it("marks openExternal as unfixable", () => {
        const strategy = resolveFixStrategy(makeSink("openExternal", ["open_redirect"]));
        expect(strategy).toBeDefined();
        expect(strategy!.applicability).toBe("unfixable");
    });

    it("recommends path containment for file-write path sinks", () => {
        const strategy = resolveFixStrategy(makeSink("writeFile_path", ["file_write"]));
        expect(strategy).toBeDefined();
        expect(strategy!.description).toContain("trusted base directory");
        expect(strategy!.description).toContain("symlinks");
    });

    it("recommends destination-context review for file integrity sinks", () => {
        const strategy = resolveFixStrategy(makeSink("writeFile_content", ["file_integrity"]));
        expect(strategy).toBeDefined();
        expect(strategy!.description).toContain("privileged consumer");
        expect(strategy!.description).not.toContain("path.resolve");
    });

    it("returns undefined for unknown sink with no matching category", () => {
        const strategy = resolveFixStrategy(makeSink("unknownSink", []));
        expect(strategy).toBeUndefined();
    });

    it("spec overrides take precedence over defaults", () => {
        const override: FixStrategy = {
            category: "rce",
            sinkName: "exec",
            saferAPI: "custom.safeExec",
            saferPattern: "safeExec(cmd)",
            applicability: "safe",
            description: "Custom override",
        };
        const strategy = resolveFixStrategy(makeSink("exec", ["rce"]), [override]);
        expect(strategy).toBeDefined();
        expect(strategy!.saferAPI).toBe("custom.safeExec");
        expect(strategy!.applicability).toBe("safe");
    });

    it("spec category-level override applies when no sinkName match", () => {
        const override: FixStrategy = {
            category: "rce",
            saferAPI: "custom.safeRun",
            saferPattern: "safeRun(cmd)",
            applicability: "safe",
            description: "Category override for all RCE",
        };
        const strategy = resolveFixStrategy(makeSink("someNewRceSink", ["rce"]), [override]);
        expect(strategy).toBeDefined();
        expect(strategy!.saferAPI).toBe("custom.safeRun");
    });
});
