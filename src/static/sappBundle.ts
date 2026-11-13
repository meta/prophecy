/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";

/** Apply the CLI's stable-handle deduplication across completed process shards. */
export async function deduplicateSappBundle(directory: string): Promise<{ kept: number; removed: number }> {
    const files = fs
        .readdirSync(directory)
        .filter((name) => /^issues_\d+\.sapp$/.test(name))
        .sort();
    if (files.length === 0) throw new Error("No issue shards found in SAPP bundle");
    const seen = new Set<string>();
    let kept = 0;
    let removed = 0;
    const staged: { file: string; temporary: string; backup: string }[] = [];
    const stagingDirectory = fs.mkdtempSync(path.join(directory, ".deduplicating-"));
    let retainStaging = false;
    try {
        for (const name of files) {
            const file = path.join(directory, name);
            const temporary = path.join(stagingDirectory, name);
            const output = fs.openSync(temporary, "wx");
            staged.push({ file, temporary, backup: temporary + ".original" });
            const input = fs.createReadStream(file);
            const lines = readline.createInterface({ input, crlfDelay: Infinity });
            let lineNumber = 0;
            try {
                for await (const line of lines) {
                    lineNumber++;
                    if (!line.trim()) continue;
                    let issue;
                    try {
                        issue = JSON.parse(line);
                    } catch (error) {
                        throw new Error(
                            `Invalid JSON in ${name}:${lineNumber}: ${error instanceof Error ? error.message : String(error)}`,
                        );
                    }
                    const handles = Array.isArray(issue?.features)
                        ? issue.features.filter(
                              (feature: unknown) =>
                                  typeof feature === "string" && feature.startsWith("prophecy-handle:"),
                          )
                        : [];
                    if (issue?.kind !== "issue" || handles.length !== 1) {
                        throw new Error(`Missing stable finding handle in ${name}:${lineNumber}`);
                    }
                    if (seen.has(handles[0])) {
                        removed++;
                    } else {
                        seen.add(handles[0]);
                        fs.writeSync(output, line + "\n");
                        kept++;
                    }
                }
            } finally {
                fs.closeSync(output);
                lines.close();
                input.destroy();
            }
        }
        // Validate and back up the entire bundle before replacing any issue shard.
        for (const { file, backup } of staged) {
            try {
                fs.copyFileSync(file, backup, fs.constants.COPYFILE_EXCL);
            } catch (error) {
                throw new Error(
                    `Could not back up ${path.basename(file)}; no issue shards were replaced: ${error instanceof Error ? error.message : String(error)}`,
                );
            }
        }
        const replaced: typeof staged = [];
        for (const entry of staged) {
            const { file, temporary } = entry;
            try {
                fs.renameSync(temporary, file);
                replaced.push(entry);
            } catch (error) {
                // Recovery handles caught I/O failures; process interruption can still leave a mixed bundle.
                const failures: string[] = [];
                for (let index = replaced.length - 1; index >= 0; index--) {
                    const original = replaced[index];
                    try {
                        fs.renameSync(original.backup, original.file);
                    } catch (restoreError) {
                        failures.push(
                            `${path.basename(original.file)}: ${restoreError instanceof Error ? restoreError.message : String(restoreError)}`,
                        );
                    }
                }
                const cause = error instanceof Error ? error.message : String(error);
                if (failures.length > 0) {
                    retainStaging = true;
                    throw new Error(
                        `Could not replace ${path.basename(file)}: ${cause}; rollback failed for ${failures.join("; ")}; recovery backups retained at ${stagingDirectory}`,
                    );
                }
                throw new Error(
                    `Could not replace ${path.basename(file)}; original issue shards restored; rerun the merge after resolving the I/O error: ${cause}`,
                );
            }
        }
    } finally {
        if (!retainStaging) fs.rmSync(stagingDirectory, { recursive: true, force: true });
    }
    // Keep every trace frame: identical handles can retain additional valid
    // paths discovered in another shard, even when their issue row is shared.
    return { kept, removed };
}
