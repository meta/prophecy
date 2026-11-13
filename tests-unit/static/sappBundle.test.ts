/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { deduplicateSappBundle } from "../../src/static/sappBundle";

describe("completed SAPP bundles", () => {
    let directory: string;
    const issue = (handle: string) =>
        JSON.stringify({ kind: "issue", handle: "same-sink", features: ["prophecy-handle:" + handle] }) + "\n";
    beforeEach(() => {
        directory = fs.mkdtempSync(path.join(os.tmpdir(), "sapp-bundle-"));
    });
    afterEach(() => {
        fs.rmSync(directory, { recursive: true, force: true });
    });

    it("deduplicates stable findings across shards while preserving different entry points and trace frames", async () => {
        fs.writeFileSync(path.join(directory, "issues_0.sapp"), issue("first") + issue("second"));
        fs.writeFileSync(path.join(directory, "issues_1.sapp"), issue("first") + issue("third"));
        const frames = '{"kind":"trace","additional-path":true}\n';
        fs.writeFileSync(path.join(directory, "traceFrames_1.sapp"), frames);
        expect(await deduplicateSappBundle(directory)).toEqual({ kept: 3, removed: 1 });
        expect(fs.readFileSync(path.join(directory, "issues_0.sapp"), "utf8")).toBe(issue("first") + issue("second"));
        expect(fs.readFileSync(path.join(directory, "issues_1.sapp"), "utf8")).toBe(issue("third"));
        expect(fs.readFileSync(path.join(directory, "traceFrames_1.sapp"), "utf8")).toBe(frames);
        expect(await deduplicateSappBundle(directory)).toEqual({ kept: 3, removed: 0 });
    });

    it("leaves earlier shards intact when a later shard is invalid, then allows retry", async () => {
        const first = path.join(directory, "issues_0.sapp");
        const second = path.join(directory, "issues_1.sapp");
        const original = issue("first") + issue("first");
        fs.writeFileSync(first, original);
        fs.writeFileSync(second, issue("first") + "invalid\n");
        await expect(deduplicateSappBundle(directory)).rejects.toThrow("Invalid JSON in issues_1.sapp:2");
        expect(fs.readFileSync(first, "utf8")).toBe(original);
        expect(fs.readdirSync(directory).sort()).toEqual(["issues_0.sapp", "issues_1.sapp"]);
        fs.writeFileSync(second, issue("first") + issue("second"));
        expect(await deduplicateSappBundle(directory)).toEqual({ kept: 2, removed: 2 });
        expect(fs.readFileSync(first, "utf8")).toBe(issue("first"));
        expect(fs.readFileSync(second, "utf8")).toBe(issue("second"));
    });

    it.each(['{"kind":"issue"}\n', "not-json\n"])(
        "rejects invalid records without replacing their shard",
        async (contents) => {
            const file = path.join(directory, "issues_0.sapp");
            fs.writeFileSync(file, contents);
            await expect(deduplicateSappBundle(directory)).rejects.toThrow();
            expect(fs.readFileSync(file, "utf8")).toBe(contents);
            expect(fs.readdirSync(directory)).toEqual(["issues_0.sapp"]);
        },
    );

    it("ignores staging files left by an interrupted invocation", async () => {
        fs.writeFileSync(path.join(directory, "issues_0.sapp"), issue("first") + issue("first"));
        fs.writeFileSync(path.join(directory, "issues_0.sapp.deduplicating"), "stale");
        fs.mkdirSync(path.join(directory, ".deduplicating-abandoned"));
        expect(await deduplicateSappBundle(directory)).toEqual({ kept: 1, removed: 1 });
        expect(fs.readFileSync(path.join(directory, "issues_0.sapp"), "utf8")).toBe(issue("first"));
    });

    it("restores original bytes in reverse order when a later replacement fails, then allows retry", async () => {
        const first = path.join(directory, "issues_0.sapp");
        const second = path.join(directory, "issues_1.sapp");
        const third = path.join(directory, "issues_2.sapp");
        const originals = [
            issue("first").replace("\n", "\r\n") + "\n" + issue("first"),
            issue("first") + issue("second"),
            issue("second") + issue("third"),
        ];
        [first, second, third].forEach((file, index) => fs.writeFileSync(file, originals[index]));
        const frames = '{"kind":"trace","additional-path":true}\n';
        const metadata = '{"project":"demo"}\n';
        fs.writeFileSync(path.join(directory, "traceFrames_1.sapp"), frames);
        fs.writeFileSync(path.join(directory, "metadata.json"), metadata);
        const rename = fs.renameSync;
        const restored: string[] = [];
        const fault = jest.spyOn(require("fs"), "renameSync").mockImplementation((from: string, to: string) => {
            if (to === third) throw new Error("simulated I/O failure");
            if (from.endsWith(".original")) restored.push(path.basename(to));
            return rename(from, to);
        });
        try {
            await expect(deduplicateSappBundle(directory)).rejects.toThrow(
                "Could not replace issues_2.sapp; original issue shards restored; rerun the merge",
            );
        } finally {
            fault.mockRestore();
        }
        expect(restored).toEqual(["issues_1.sapp", "issues_0.sapp"]);
        [first, second, third].forEach((file, index) => expect(fs.readFileSync(file, "utf8")).toBe(originals[index]));
        expect(fs.readFileSync(path.join(directory, "traceFrames_1.sapp"), "utf8")).toBe(frames);
        expect(fs.readFileSync(path.join(directory, "metadata.json"), "utf8")).toBe(metadata);
        expect(fs.readdirSync(directory).sort()).toEqual([
            "issues_0.sapp",
            "issues_1.sapp",
            "issues_2.sapp",
            "metadata.json",
            "traceFrames_1.sapp",
        ]);
        expect(await deduplicateSappBundle(directory)).toEqual({ kept: 3, removed: 3 });
        expect(fs.readFileSync(first, "utf8")).toBe(issue("first"));
        expect(fs.readFileSync(second, "utf8")).toBe(issue("second"));
        expect(fs.readFileSync(third, "utf8")).toBe(issue("third"));
    });

    it("does not replace any shard when preparing a later backup fails", async () => {
        const first = path.join(directory, "issues_0.sapp");
        const second = path.join(directory, "issues_1.sapp");
        const originals = [issue("first") + issue("first"), issue("first") + issue("second")];
        fs.writeFileSync(first, originals[0]);
        fs.writeFileSync(second, originals[1]);
        const copy = fs.copyFileSync;
        const fault = jest
            .spyOn(require("fs"), "copyFileSync")
            .mockImplementation((from: string, to: string, flags?: number) => {
                if (from === second) throw new Error("simulated backup failure");
                return copy(from, to, flags);
            });
        const rename = jest.spyOn(require("fs"), "renameSync");
        try {
            await expect(deduplicateSappBundle(directory)).rejects.toThrow(
                "Could not back up issues_1.sapp; no issue shards were replaced",
            );
            expect(rename).not.toHaveBeenCalled();
        } finally {
            fault.mockRestore();
            rename.mockRestore();
        }
        expect(fs.readFileSync(first, "utf8")).toBe(originals[0]);
        expect(fs.readFileSync(second, "utf8")).toBe(originals[1]);
        expect(fs.readdirSync(directory).sort()).toEqual(["issues_0.sapp", "issues_1.sapp"]);
        expect(await deduplicateSappBundle(directory)).toEqual({ kept: 2, removed: 2 });
    });

    it("continues rollback and retains usable backups when one restore fails", async () => {
        const first = path.join(directory, "issues_0.sapp");
        const second = path.join(directory, "issues_1.sapp");
        const third = path.join(directory, "issues_2.sapp");
        const originals = [
            issue("first") + issue("first"),
            issue("first") + issue("second"),
            issue("second") + issue("third"),
        ];
        [first, second, third].forEach((file, index) => fs.writeFileSync(file, originals[index]));
        const rename = fs.renameSync;
        const fault = jest.spyOn(require("fs"), "renameSync").mockImplementation((from: string, to: string) => {
            if (to === third) throw new Error("simulated replacement failure");
            if (from.endsWith(".original") && to === second) throw new Error("simulated restore failure");
            return rename(from, to);
        });
        let failure: Error | undefined;
        try {
            await deduplicateSappBundle(directory);
        } catch (error) {
            failure = error as Error;
        } finally {
            fault.mockRestore();
        }
        expect(failure).toBeInstanceOf(Error);
        expect(failure?.message).toContain("Could not replace issues_2.sapp: simulated replacement failure");
        expect(failure?.message).toContain("rollback failed for issues_1.sapp: simulated restore failure");
        const recovery = fs.readdirSync(directory).find((name) => name.startsWith(".deduplicating-"));
        if (!recovery) throw new Error("Expected retained recovery backups");
        const recoveryDirectory = path.join(directory, recovery);
        expect(failure?.message).toContain("recovery backups retained at " + recoveryDirectory);
        expect(fs.readFileSync(first, "utf8")).toBe(originals[0]);
        expect(fs.readFileSync(second, "utf8")).toBe(issue("second"));
        expect(fs.readFileSync(third, "utf8")).toBe(originals[2]);
        expect(fs.readFileSync(path.join(recoveryDirectory, "issues_1.sapp.original"), "utf8")).toBe(originals[1]);
        expect(fs.readFileSync(path.join(recoveryDirectory, "issues_2.sapp.original"), "utf8")).toBe(originals[2]);
        fs.renameSync(path.join(recoveryDirectory, "issues_1.sapp.original"), second);
        expect(await deduplicateSappBundle(directory)).toEqual({ kept: 3, removed: 3 });
    });
});
