/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
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
        fileName: "/src/dispatch.ts",
        spec,
        maxDepth: 8,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("concrete receiver dispatch regressions", () => {
    it("does not dispatch a concrete safe interface receiver to another implementation", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            class Safe implements Runner { run(input: string) { exec("fixed"); } }
            class Unsafe implements Runner { run(input: string) { exec(input); } }
            function invoke(runner: Runner, input: string) { runner.run(input); }
            register(input => invoke(new Safe(), input));
        `),
        ).toHaveLength(0);
    });

    it("dispatches a base-class method with a body to a concrete override", async () => {
        expect(
            await check(`
            class Base { run(input: string) { exec("fixed"); } }
            class Derived extends Base { run(input: string) { exec(input); } }
            function invoke(runner: Base, input: string) { runner.run(input); }
            register(input => invoke(new Derived(), input));
        `),
        ).toHaveLength(1);
    });

    it("dispatches virtual calls from a base method on the concrete this receiver", async () => {
        expect(
            await check(`
            class Base {
                run(input: string) { this.consume(input); }
                consume(input: string) { exec("fixed"); }
            }
            class Derived extends Base { consume(input: string) { exec(input); } }
            register(input => new Derived().run(input));
        `),
        ).toHaveLength(1);
    });

    it("does not virtually dispatch explicit super method and constructor calls", async () => {
        expect(
            await check(`
            class Base { constructor(input: string) {} run(input: string) { exec("fixed"); } }
            class Derived extends Base {
                constructor(input: string) { super(input); }
                run(input: string) { exec(input); }
                baseOnly(input: string) { super.run(input); }
            }
            register(input => new Derived(input).baseOnly(input));
        `),
        ).toHaveLength(0);
    });

    it("retains separate fields for two instances of the same concrete implementation", async () => {
        expect(
            await check(`
            interface Runner { run(): void }
            class RunnerImpl implements Runner {
                constructor(private command: string) {}
                run() { exec(this.command); }
            }
            function invoke(runner: Runner) { runner.run(); }
            register(input => {
                const unsafe = new RunnerImpl(input);
                const safe = new RunnerImpl("fixed");
                invoke(safe);
            });
        `),
        ).toHaveLength(0);
    });

    it("isolates effects between alternative concrete implementations", async () => {
        expect(
            await check(`
            class Base { command = "fixed"; run(input: string) {} }
            class Write extends Base { run(input: string) { this.command = input; } }
            class Read extends Base { run(input: string) { exec(this.command); } }
            register(input => {
                const target: Base = input ? new Write() : new Read();
                target.run(input);
            });
        `),
        ).toHaveLength(0);
    });

    it("joins alternative receiver effects for reads after the dispatch", async () => {
        expect(
            await check(`
            class Base { command = "fixed"; run(input: string) {} }
            class Write extends Base { run(input: string) { this.command = input; } }
            class Read extends Base { run(input: string) { exec(this.command); } }
            register(input => {
                const target: Base = input ? new Write() : new Read();
                target.run(input);
                exec(target.command);
            });
        `),
        ).toHaveLength(1);
    });

    it("isolates argument effects between alternatives and joins them afterward", async () => {
        const findings = await check(`
            class Box { command = "fixed"; }
            class Base { run(input: string, box: Box) {} }
            class Write extends Base { run(input: string, box: Box) { box.command = input; } }
            class Read extends Base { run(input: string, box: Box) { exec(box.command); } }
            register(input => {
                const target: Base = input ? new Write() : new Read();
                const box = new Box();
                target.run(input, box);
                exec(box.command);
            });
        `);
        expect(findings).toHaveLength(1);
        expect(findings[0].sinkSite).not.toContain("Read");
    });

    it("commits nested writes to an alias retained outside alternative receiver roots", async () => {
        expect(
            await check(`
            class Box { command = "fixed"; }
            class Base { constructor(public box: Box) {} run(input: string) {} }
            class Write extends Base { run(input: string) { this.box.command = input; } }
            class Idle extends Base { run(input: string) {} }
            register(input => {
                const box = new Box();
                const target: Base = input ? new Write(box) : new Idle(box);
                target.run(input);
                exec(box.command);
            });
        `),
        ).toHaveLength(1);
    });

    it("isolates lazy module hosts between alternative implementations", async () => {
        expect(
            await check(`
            import {EventEmitter} from "events";
            const bus = new EventEmitter();
            class Base { run(input: string) {} }
            class Subscribe extends Base { run(input: string) { bus.on("run", value => exec(value)); } }
            class Emit extends Base { run(input: string) { bus.emit("run", input); } }
            register(input => {
                const target: Base = input ? new Subscribe() : new Emit();
                target.run(input);
            });
        `),
        ).toHaveLength(0);
    });

    it("keeps known interface formatter returns clean instead of open-world passthrough", async () => {
        expect(
            await check(`
            interface Formatter { format(input: string): string }
            class Fixed implements Formatter { format(input: string) { return "fixed"; } }
            function invoke(formatter: Formatter, input: string) { exec(formatter.format(input)); }
            register(input => invoke(new Fixed(), input));
        `),
        ).toHaveLength(0);
    });

    it("resolves function-valued interface property signatures and literal method access", async () => {
        expect(
            await check(`
            interface Runner { run: (input: string) => void }
            class Unsafe implements Runner { run = (input: string) => { exec(input); }; }
            function invoke(runner: Runner, input: string) { runner["run"](input); }
            register(input => invoke(new Unsafe(), input));
        `),
        ).toHaveLength(1);
    });

    it("does not impose the open-hierarchy candidate cap on a concrete receiver", async () => {
        expect(
            await check(`
            interface Runner { run(input: string): void }
            class Unsafe implements Runner { run(input: string) { exec(input); } }
            ${Array.from({ length: 9 }, (_, i) => `class Safe${i} implements Runner { run(input: string) {} }`).join("\n")}
            function invoke(runner: Runner, input: string) { runner.run(input); }
            register(input => invoke(new Unsafe(), input));
        `),
        ).toHaveLength(1);
    });

    it("preserves the concrete class across an imported factory and interface boundary", async () => {
        const result = await analyze({
            projectDir: path.join(__dirname, "fixtures/dispatch-concrete-cross-file"),
            spec,
            maxDepth: 8,
            outputFormat: "text",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.fileName).toContain("runners.ts");
        expect(new Set(result.findings[0].propagationChain.map((step) => step.location.fileName)).size).toBeGreaterThan(
            1,
        );
    });
});
