/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { ExecSink } from "../../src/static/spec/sinks";
import { TaintSpec } from "../../src/static/spec/types";

const spec: TaintSpec = {
    sources: [
        {
            kind: "parameter",
            pattern: "register.input",
            description: "External input",
            callbackRegistration: "register",
            paramIndex: 0,
            taintAllProperties: true,
        },
    ],
    sinks: [ExecSink],
    sanitizers: [],
};

async function check(source: string) {
    const result = await analyze({
        source: `import { exec } from "child_process"; declare function register(callback: (input: string) => void): void; ${source}`,
        fileName: "/src/dispatch-stored-callback.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings.map((finding) => finding.sinkLocation.line).sort((a, b) => a - b);
}

// The queue is reached through a parameter, so no tracked instance holds its callback.
const enqueue = `declare const queue: Queue;
    register(input => queue.enqueue(input));`;

describe("calls through a callback stored in a class field", () => {
    it("reaches a callback passed for a constructor parameter property", async () => {
        expect(
            await check(`
            class Queue {
                constructor(private run: (input: string) => void) {}
                enqueue(input: string) { this.run(input); }
            }
            class Owner { private queue = new Queue(input => { exec(input); }); }
            ${enqueue}
        `),
        ).toEqual([6]);
    });

    it("reaches a callback a subclass passes to super", async () => {
        expect(
            await check(`
            class Queue {
                constructor(protected run: (input: string) => void) {}
                enqueue(input: string) { this.run(input); }
            }
            class Unsafe extends Queue { constructor() { super(input => { exec(input); }); } }
            ${enqueue}
        `),
        ).toEqual([6]);
    });

    it("reaches callbacks assigned to a declared field", async () => {
        expect(
            await check(`
            function named(input: string) { exec(input); }
            class Queue {
                run: (input: string) => void;
                constructor() { this.run = input => { exec(input); }; }
                enqueue(input: string) { this.run(input); }
            }
            function install(target: Queue) { target.run = named; }
            ${enqueue}
        `),
        ).toEqual([2, 5]);
    });

    it("reaches a callback passed to an overloaded constructor", async () => {
        expect(
            await check(`
            class Queue {
                constructor(run: (input: string) => void);
                constructor(run: (input: string) => void, name: string);
                constructor(private run: (input: string) => void, private name?: string) {}
                enqueue(input: string) { this.run(input); }
            }
            const unsafe = new Queue(input => { exec(input); });
            ${enqueue}
        `),
        ).toEqual([8]);
    });

    it("keeps a field's own initializer as the precise target when more callbacks are stored than fit", async () => {
        const assignments = Array.from(
            { length: 9 },
            (_, index) => `function install${index}(target: Queue) { target.convert = input => "fixed"; }`,
        ).join("\n");
        const findings = await check(`
            class Queue {
                convert = (input: string) => { exec(input); return "fixed"; };
                enqueue(input: string) { exec(this.convert(input)); }
            }
            ${assignments}
            ${enqueue}
        `);
        // The initializer's own sink reports; its fixed result does not become tainted by passthrough.
        expect(findings).toEqual([3]);
    });

    it("reaches a callback stored in a field of a class that implements the receiver's interface", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            class Assigned implements Runner {
                run: (input: string) => void;
                constructor() { this.run = input => { exec(input); }; }
            }
            class Constructed implements Runner {
                constructor(public run: (input: string) => void) {}
            }
            const constructed = new Constructed(input => { exec(input); });
            declare const runner: Runner;
            register(input => runner.run(input));
        `),
        ).toEqual([5, 10]);
    });

    it("does not reach a safe callback or one stored in another class", async () => {
        expect(
            await check(`
            class Queue {
                constructor(private run: (input: string) => void) {}
                enqueue(input: string) { this.run(input); }
            }
            class Other { constructor(private run: (input: string) => void) {} }
            const safe = new Queue(input => { exec("fixed"); });
            const other = new Other(input => { exec(input); });
            ${enqueue}
        `),
        ).toEqual([]);
    });

    // Known limit: only declared fields and parameter properties are indexed.
    it("does not reach a callback copied from a plain constructor parameter", async () => {
        expect(
            await check(`
            class Queue {
                private run: (input: string) => void;
                constructor(run: (input: string) => void) { this.run = run; }
                enqueue(input: string) { this.run(input); }
            }
            const unsafe = new Queue(input => { exec(input); });
            ${enqueue}
        `),
        ).toEqual([]);
    });

    it.each([
        [8, 8],
        [9, 0],
    ])("analyzes %i stored callbacks and reports %i", async (count, expected) => {
        const queues = Array.from(
            { length: count },
            (_, index) => `const queue${index} = new Queue(input => { exec(input); });`,
        ).join("\n");
        expect(
            await check(`
            class Queue {
                constructor(private run: (input: string) => void) {}
                enqueue(input: string) { this.run(input); }
            }
            ${queues}
            ${enqueue}
        `),
        ).toHaveLength(expected);
    });
});
