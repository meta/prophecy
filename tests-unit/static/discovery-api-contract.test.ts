/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { ExecSink } from "../../src/static/spec/sinks";
import { SourceSpec, TaintSpec } from "../../src/static/spec/types";

const message: SourceSpec = {
    kind: "parameter",
    pattern: "message.payload",
    description: "Message payload",
    callbackRegistration: "onMessage",
    callbackMatch: "api",
    callbackArgIndex: 1,
    paramIndex: 0,
    taintAllProperties: true,
};
async function check(body: string) {
    const spec: TaintSpec = { sources: [message], sinks: [ExecSink], sanitizers: [] };
    const result = await analyze({
        source: `import { exec } from "child_process"; ${body}`,
        fileName: "/src/discovery.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("identity-qualified callback discovery", () => {
    it("does not seed arbitrary EventEmitter message callbacks", async () => {
        expect(
            await check(`
            import { EventEmitter } from "events";
            const emitter = new EventEmitter();
            emitter.on("message", payload => exec(payload));
        `),
        ).toHaveLength(0);
    });
    it("keeps proven WebSocket message callbacks as external entry points", async () => {
        expect(
            await check(`
            import WebSocket from "ws";
            const socket = new WebSocket("wss://example.test");
            socket.on("message", payload => exec(payload));
        `),
        ).toHaveLength(1);
    });
});
