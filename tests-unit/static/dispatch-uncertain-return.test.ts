/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
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
const prelude = `
    import {exec} from "child_process";
    declare function register(callback: (input: string) => void): void;
    interface Runner { noop(): void; run?(input: string): void; }
    class FileRunner implements Runner {
        static instance: FileRunner;
        static getInstance(): FileRunner {
            if (!FileRunner.instance) FileRunner.instance = new FileRunner();
            return FileRunner.instance;
        }
        noop(): void {}
        run(input: string): void { exec(input); }
    }
    class NoopRunner implements Runner { noop(): void {} }
    declare function opaque(): Runner;
    declare function text(): string;
`;

describe("mixed known and unknown receiver dispatch", () => {
    it.each([
        {
            name: "retains an unknown singleton return beside a known allocation",
            body: `function choose(flag: boolean): Runner {
                if (flag) return FileRunner.getInstance();
                return new NoopRunner();
            }
            choose(Boolean(input)).run?.(input);`,
            expected: 1,
        },
        {
            name: "retains an opaque factory return beside a known allocation",
            body: `function choose(flag: boolean): Runner {
                if (flag) return opaque();
                return new NoopRunner();
            }
            choose(Boolean(input)).run?.(input);`,
            expected: 1,
        },
        {
            name: "retains both directly allocated alternatives",
            body: `function choose(flag: boolean): Runner {
                if (flag) return new FileRunner();
                return new NoopRunner();
            }
            choose(Boolean(input)).run?.(input);`,
            expected: 1,
        },
        {
            name: "does not widen an exhaustive known receiver",
            body: `function choose(): Runner { return new NoopRunner(); }
                choose().run?.(input);`,
            expected: 0,
        },
        {
            name: "does not treat null as an unknown object alternative",
            body: `function choose(flag: boolean): Runner | null {
                if (flag) return null;
                return new NoopRunner();
            }
            choose(Boolean(input))?.run?.(input);`,
            expected: 0,
        },
        {
            name: "does not treat undefined as an unknown object alternative",
            body: `function choose(flag: boolean): Runner | undefined {
                if (flag) return undefined;
                return new NoopRunner();
            }
            choose(Boolean(input))?.run?.(input);`,
            expected: 0,
        },
        {
            name: "does not treat an unknown primitive as an unknown object alternative",
            body: `function choose(flag: boolean): Runner | string {
                    if (flag) return text();
                    return new NoopRunner();
                }
                (choose(Boolean(input)) as Runner).run?.(input);`,
            expected: 0,
        },
        {
            name: "preserves known this identity even when scalar return cleanliness is unknown",
            body: `class Safe implements Runner {
                noop(): void {}
                self(): Runner { return this; }
                run(_input: string): void { exec("fixed"); }
            }
            new Safe().self().run?.(input);`,
            expected: 0,
        },
        {
            name: "does not leak definition-site closure uncertainty into a known return",
            body: `function choose(): Runner {
                const deferred = () => { return opaque(); };
                return new NoopRunner();
            }
            choose().run?.(input);`,
            expected: 0,
        },
        {
            name: "does not mark an original known alias uncertain when returning a mixed value",
            body: `const safe = new NoopRunner();
                function choose(flag: boolean): Runner {
                    if (flag) return opaque();
                    return safe;
                }
                const mixed = choose(Boolean(input));
                (safe as Runner).run?.(input);`,
            expected: 0,
        },
        {
            name: "carries mixed receiver uncertainty through an alias and branch fork",
            body: `function choose(flag: boolean): Runner {
                if (flag) return opaque();
                return new NoopRunner();
            }
            const mixed = choose(Boolean(input));
            if (input) { const alias = mixed; alias.run?.(input); }`,
            expected: 1,
        },
        {
            name: "preserves an unknown conditional alternative without a function return",
            body: `const safe = new NoopRunner();
                const mixed: Runner = input ? opaque() : safe;
                mixed.run?.(input);`,
            expected: 1,
        },
        {
            name: "keeps a nullable conditional known receiver precise",
            body: `const safe = new NoopRunner();
                const selected: Runner | null = input ? null : safe;
                selected?.run?.(input);`,
            expected: 0,
        },
        {
            name: "carries uncertainty through an expression-bodied returned value",
            body: `const choose = (flag: boolean): Runner => flag ? opaque() : new NoopRunner();
                choose(Boolean(input)).run?.(input);`,
            expected: 1,
        },
        {
            name: "records untracked object returns independently of scalar taint",
            body: `const object = JSON.parse(input) as Runner;
                function choose(flag: boolean): Runner {
                    if (flag) return object;
                    return new NoopRunner();
                }
                choose(Boolean(input)).run?.(input);`,
            expected: 1,
        },
    ])("$name", async ({ body, expected }) => {
        const result = await analyze({
            source: prelude + `register(input => { ${body} });`,
            fileName: "/src/dispatch-uncertain-return.ts",
            spec,
            maxDepth: 8,
            outputFormat: "text",
        });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(expected);
    });

    it("projects nullable interface receivers in a strict project", async () => {
        const projectDir = path.join(__dirname, "fixtures/dispatch-strict-nullable");
        const parsed = parseProject(projectDir);
        expect(parsed.program.getCompilerOptions().strict).toBe(true);
        expect(parsed.program.getSemanticDiagnostics()).toEqual([]);
        // Analyze each entry separately: their shared sink and source pattern otherwise deduplicate.
        for (const [line, expected] of [
            [15, 1],
            [16, 1],
            [17, 0],
        ]) {
            const result = await analyze({
                projectDir,
                spec,
                maxDepth: 8,
                outputFormat: "text",
                entryPointFilter: [`main.ts:${line}`],
            });
            expect(result.syntaxErrors).toEqual([]);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.entryPointCount).toBe(1);
            expect(result.findings).toHaveLength(expected);
        }
    });
});
