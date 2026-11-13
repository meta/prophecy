/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as path from "path";
import { execFile as execFileCb } from "child_process";
import { promisify } from "util";

const execFile = promisify(execFileCb);

export const SAPLING_COMMAND_TIMEOUT_MS = 10_000;

interface CommandOptions {
    cwd?: string;
    timeout?: number;
}

/** Run a command without a shell and normalize stderr/process failures. */
export async function runCommand(command: string, args: string[], options: CommandOptions = {}): Promise<string> {
    try {
        const { stdout } = await execFile(command, args, {
            cwd: options.cwd,
            encoding: "utf-8",
            env: process.env,
            timeout: options.timeout,
        });
        return stdout;
    } catch (error: any) {
        const message = error?.stderr?.trim() || error?.message || String(error);
        throw new Error(`${command} ${args.join(" ")} failed: ${message}`);
    }
}

/** Run Sapling with the shared timeout used by analysis and reporting. */
export function runSaplingCommand(args: string[], options: Omit<CommandOptions, "timeout"> = {}): Promise<string> {
    return runCommand("sl", args, {
        ...options,
        timeout: SAPLING_COMMAND_TIMEOUT_MS,
    });
}

/** Return the current Sapling node, or undefined when it cannot be resolved. */
export async function getSaplingRevision(repoRoot: string | undefined): Promise<string | undefined> {
    if (!repoRoot) {
        return undefined;
    }

    try {
        const stdout = await runSaplingCommand(["log", "-r", ".", "-T", "{node}"], { cwd: repoRoot });
        return stdout.trim() || undefined;
    } catch {
        return undefined;
    }
}

/** Find the nearest ancestor marked as a repository root by `.arcconfig`. */
export function findNearestArcConfigRoot(startPath: string): string | undefined {
    let current = startDirectory(startPath);

    while (true) {
        if (fs.existsSync(path.join(current, ".arcconfig"))) {
            return current;
        }

        const parent = path.dirname(current);
        if (parent === current) return undefined;
        current = parent;
    }
}

function startDirectory(startPath: string): string {
    const resolved = path.resolve(startPath);
    try {
        if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
            return resolved;
        }
    } catch {
        // Fall through to the containing directory.
    }
    return path.dirname(resolved);
}

export function parseUnifiedDiffPaths(rawDiff: string): string[] {
    const paths = new Set<string>();
    const lines = rawDiff.split("\n");
    // split adds a sentinel after the final newline; it is not a context line.
    if (lines[lines.length - 1] === "") lines.pop();
    let gitPath: string | undefined;
    let oldRemaining = 0;
    let newRemaining = 0;
    let sawHeader = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].replace(/\r$/, "");
        if (oldRemaining > 0 || newRemaining > 0) {
            // Some diff producers omit the space prefix on empty context lines.
            if (line.startsWith(" ") || line === "") {
                oldRemaining--;
                newRemaining--;
            } else if (line.startsWith("-")) oldRemaining--;
            else if (line.startsWith("+")) newRemaining--;
            else if (!line.startsWith("\\")) throw new Error("Malformed unified diff hunk");
            if (oldRemaining < 0 || newRemaining < 0) throw new Error("Malformed unified diff hunk");
            continue;
        }

        const hunk = /^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
        if (hunk) {
            oldRemaining = Number(hunk[1] ?? 1);
            newRemaining = Number(hunk[2] ?? 1);
            continue;
        }

        if (line.startsWith("diff --git ")) {
            const match = /^diff --git (?:"(?:[^"\\]|\\.)*"|a\/.+) ("(?:[^"\\]|\\.)*"|b\/.+)$/.exec(line);
            if (!match) throw new Error(`Unsupported Git diff header: ${line}`);
            gitPath = decodeDiffPath(match[1]).replace(/^b\//, "");
            paths.add(normalizeRepoRelativePath(gitPath));
            sawHeader = true;
        } else if (line.startsWith("--- ")) {
            const next = lines[++i]?.replace(/\r$/, "");
            if (!next?.startsWith("+++ ")) throw new Error("Unified diff is missing its +++ file header");
            const oldPath = decodeDiffPath(line.slice(4).split("\t")[0]);
            let newPath = decodeDiffPath(next.slice(4).split("\t")[0]);
            if (gitPath) paths.delete(normalizeRepoRelativePath(gitPath));
            if (newPath !== "/dev/null") {
                if (gitPath || (oldPath.startsWith("a/") && newPath.startsWith("b/"))) {
                    newPath = newPath.replace(/^b\//, "");
                }
                paths.add(normalizeRepoRelativePath(newPath));
            }
            gitPath = undefined;
            sawHeader = true;
        }
    }

    if (oldRemaining > 0 || newRemaining > 0) throw new Error("Truncated unified diff hunk");
    if (rawDiff.trim() && !sawHeader) throw new Error("No supported file headers found in patch");
    return [...paths];
}

/** Git quotes paths using C escapes, including octal UTF-8 bytes. */
function decodeDiffPath(value: string): string {
    if (!value.startsWith('"')) return value;
    if (!value.endsWith('"')) throw new Error("Unterminated quoted diff path");
    const escapes: Record<string, string> = {
        a: "\x07",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
        v: "\v",
        "\\": "\\",
        '"': '"',
    };
    const pieces = value.slice(1, -1).split(/(\\[0-7]{1,3}|\\.)/);
    return Buffer.concat(
        pieces.map((piece) => {
            if (!piece.startsWith("\\")) return Buffer.from(piece);
            if (/^\\[0-7]{1,3}$/.test(piece)) return Buffer.from([parseInt(piece.slice(1), 8)]);
            const escaped = escapes[piece[1]];
            if (escaped == null) throw new Error(`Unsupported escape in diff path: ${piece}`);
            return Buffer.from(escaped);
        }),
    ).toString("utf8");
}

export function normalizeRepoRelativePath(filePath: string): string {
    return filePath.replace(/^(\.\/)+/, "").replace(/\\/g, "/");
}
