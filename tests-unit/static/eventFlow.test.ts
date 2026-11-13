/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { analyzeFixture, vscodeSpecWithEnvSource } from "./testUtils";

async function analyzeFlow(body: string, helpers = "") {
    return analyze({
        source: `import { exec } from "child_process";
            import { EventEmitter } from "node:events";
            import { PassThrough } from "node:stream";
            ${helpers}
            export function activate() { ${body} }`,
        fileName: "/src/eventFlow.ts",
        spec: vscodeSpecWithEnvSource,
        outputFormat: "text",
        maxDepth: 8,
    });
}

describe("eventFlow object-scoped host models", () => {
    it("connects factories and producers/consumers across files", async () => {
        const result = await analyzeFixture("eventFlow", { spec: vscodeSpecWithEnvSource, maxDepth: 10 });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(4);
        expect(result.findings.every((finding) => /(?:channels|shared)\.ts$/.test(finding.sinkLocation.fileName))).toBe(
            true,
        );
        expect(
            result.findings.every(
                (finding) => new Set(finding.propagationChain.map((step) => step.location.fileName)).size >= 2,
            ),
        ).toBe(true);
    });

    it.each([
        [
            "event callback",
            "const bus = new EventEmitter(); bus.on('command', value => exec(value)); bus.emit('command', process.env.INPUT);",
        ],
        ["cross-function event", "const bus = new EventEmitter(); consume(bus); produce(bus, process.env.INPUT);"],
        [
            "factory-returned event callback",
            "const bus = new EventEmitter(); bus.on('command', make()); bus.emit('command', process.env.INPUT);",
        ],
        [
            "stream callback",
            "const stream = new PassThrough(); stream.on('data', value => exec(value)); stream.write(process.env.INPUT);",
        ],
        [
            "buffered stream across functions",
            "const stream = new PassThrough(); write(stream, process.env.INPUT); read(stream);",
        ],
        [
            "piped stream across functions",
            "const a = new PassThrough(); const b = new PassThrough(); a.pipe(b); read(b); write(a, process.env.INPUT);",
        ],
        [
            "listener survives branch",
            "const bus = new EventEmitter(); if (process.env.MODE) consume(bus); produce(bus, process.env.INPUT);",
        ],
        ["stream end data", "const stream = new PassThrough(); read(stream); stream.end(process.env.INPUT);"],
    ])("propagates %s", async (_name, body) => {
        const result = await analyzeFlow(
            body,
            `
            function consume(bus: EventEmitter) { bus.on('command', value => exec(value)); }
            function produce(bus: EventEmitter, value: string) { bus.emit('command', value); }
            function make() { return (value: string) => exec(value); }
            function write(stream: PassThrough, value: string) { stream.write(value); }
            function read(stream: PassThrough) { stream.on('data', value => exec(value)); }
        `,
        );
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each([
        [
            "unrelated instance",
            "const a = new EventEmitter(); const b = new EventEmitter(); b.on('command', value => exec(value)); a.emit('command', process.env.INPUT);",
        ],
        [
            "unrelated event",
            "const bus = new EventEmitter(); bus.on('other', value => exec(value)); bus.emit('command', process.env.INPUT);",
        ],
        [
            "clean event",
            "const bus = new EventEmitter(); bus.on('command', value => exec(value)); bus.emit('command', 'fixed');",
        ],
        [
            "unrelated stream",
            "const a = new PassThrough(); const b = new PassThrough(); b.on('data', value => exec(value)); a.write(process.env.INPUT);",
        ],
        [
            "message is not a universal source",
            "const bus = new EventEmitter(); bus.on('message', value => exec(value)); bus.emit('message', 'fixed');",
        ],
        [
            "unrelated on/emit object",
            "const bus = { on: (_name: string, _cb: any) => {}, emit: (_name: string, _value: string) => {} }; bus.on('command', value => exec(value)); bus.emit('command', process.env.INPUT);",
        ],
        [
            "past event is not buffered",
            "const bus = new EventEmitter(); bus.emit('command', process.env.INPUT); bus.on('command', value => exec(value));",
        ],
        [
            "once listener removed",
            "const bus = new EventEmitter(); bus.once('command', value => exec(value)); bus.emit('command', 'fixed'); bus.emit('command', process.env.INPUT);",
        ],
        [
            "consumed stream data",
            "const stream = new PassThrough(); stream.on('data', () => {}); stream.write(process.env.INPUT); stream.on('data', value => exec(value));",
        ],
        [
            "unrelated stream event",
            "const stream = new PassThrough(); stream.on('open', value => exec(value)); stream.write(process.env.INPUT);",
        ],
    ])("keeps %s clean", async (_name, body) => {
        const result = await analyzeFlow(body);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });
});
