/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import * as fs from "fs";
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";
import { InterproceduralAnalyzer } from "../../src/static/taint/interprocedural";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

describe("typed WebSocket discovery from nested package declarations", () => {
    it("uses the innermost package owner for parameters and typed fields, not local lookalikes", async () => {
        const dir = apiBoundaryFixture(
            {
                "main.ts": `
            import WebSocket from "./node_modules/wrapper/node_modules/@types/ws";
            import {exec} from "child_process";
            export function bind(socket: WebSocket) {
                socket.on("message", data => exec(data));
            }
            export class Adapter {
                constructor(private socket: WebSocket) {}
                bind() { this.socket.once("message", data => exec(data)); }
            }
            class LocalSocket { on(event: string, callback: (value: string) => void) {} }
            export function unrelated(socket: LocalSocket) {
                socket.on("message", data => exec(data));
            }
        `,
            },
            'declare module "child_process" { export function exec(command: string): void; }',
        );
        try {
            const packageDir = path.join(dir, "node_modules/wrapper/node_modules/@types/ws");
            fs.mkdirSync(packageDir, { recursive: true });
            fs.writeFileSync(
                path.join(packageDir, "index.d.ts"),
                `
                declare class WebSocket {
                    on(event: string, callback: (data: string) => void): this;
                    once(event: string, callback: (data: string) => void): this;
                }
                export = WebSocket;
            `,
            );
            const { checker, sourceFiles } = parseProject(dir);
            const entries = new InterproceduralAnalyzer(checker, vscodeExtensionSpec).discoverEntryPoints(sourceFiles);
            expect(entries).toHaveLength(2);
            expect(entries.every((entry) => entry.taintedParams.has(0))).toBe(true);
            const result = await analyze({ projectDir: dir, spec: vscodeExtensionSpec, outputFormat: "text" });
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings).toHaveLength(2);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
