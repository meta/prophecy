/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { vscodeSpecWithEnvSource } from "./testUtils";

async function scan(body: string) {
    return analyze({
        source: `import { exec } from "child_process";
            import * as fs from "fs";
            declare const flag: boolean;
            export async function activate() { ${body} }`,
        fileName: "/src/arrayFromRegression.ts",
        spec: vscodeSpecWithEnvSource,
        maxDepth: 8,
        outputFormat: "text",
    });
}

describe("native Array.from array-like mapping", () => {
    it("retains passthrough when another module replaces constructor behavior", async () => {
        const result = await analyze({
            projectDir: path.join(__dirname, "fixtures/array-from-overrides"),
            spec: vscodeSpecWithEnvSource,
            maxDepth: 8,
            outputFormat: "text",
            requireTypes: true,
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.syntaxErrors).toEqual([]);
        expect(result.typeEnvironmentWarning).toBeUndefined();
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.pattern).toBe("fs.readFileSync");
    });

    it("does not transfer cache-header cardinality to generated shard suffixes through a worker", async () => {
        const result = await scan(`
            async function runWorkers<T>(items: T[], work: (item: T) => Promise<unknown>) {
                let next = 0;
                async function worker() {
                    while (next < items.length) {
                        const i = next++;
                        await work(items[i]);
                    }
                }
                await worker();
            }
            function shardPath(shard: number) { return '/cache/view.s' + shard + '.json'; }
            async function readCache() {
                const header = JSON.parse(await fs.promises.readFile('/cache/header.json', 'utf8'));
                const count = header.shardCount;
                if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) return;
                const indices = Array.from({length: count}, (_, i) => i);
                await runWorkers(indices, async i => fs.promises.readFile(shardPath(i), 'utf8'));
            }
            await readCache();
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it("keeps the element undefined and applies a mapper default instead of passing length", async () => {
        const result = await scan(`
            const rows = Array.from({length: process.env.COUNT}, (value = process.env.INPUT, i) => value);
            exec(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].source.pattern).toBe("process.env");
        expect(result.findings[0].propagationChain.some((step) => step.description.includes("default value"))).toBe(
            true,
        );
    });

    it("derives mapped object fields from mapper returns", async () => {
        const result = await scan(`
            const rows = Array.from({length: process.env.COUNT}, (_, i) => ({
                index: i, command: fs.readFileSync('/cache/command', 'utf8')
            }));
            exec(rows[0].command);
            fs.readFileSync('/cache/view.s' + rows[0].index + '.json');
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.text).toBe("exec(rows[0].command)");
    });

    it("analyzes mapper side-effect sinks without substituting them for returned indices", async () => {
        const result = await scan(`
            const content = fs.readFileSync('/cache/command', 'utf8');
            const rows = Array.from({length: process.env.COUNT}, (_, i) => { exec(content); return i; });
            fs.readFileSync('/cache/view.s' + rows[0] + '.json');
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.text).toBe("exec(content)");
    });

    it("preserves mapper thisArg and captured instance effects", async () => {
        const result = await scan(`
            const context = {command: process.env.INPUT};
            const box = {command: 'fixed'};
            const rows = Array.from({length: process.env.COUNT}, function (_, i) {
                box.command = this.command;
                return i;
            }, context);
            exec(box.command);
            fs.readFileSync('/cache/view.s' + rows[0] + '.json');
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.text).toBe("exec(box.command)");
    });

    it("joins observed mapper return taint with incomplete return passthrough", async () => {
        const result = await scan(`
            declare function external(): string;
            const rows = Array.from({length: process.env.COUNT}, (_, i) => {
                if (flag) return fs.readFileSync('/cache/command', 'utf8');
                return external();
            });
            fs.readFileSync(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.some((f) => f.source.pattern === "process.env")).toBe(true);
        expect(result.findings.some((f) => f.source.pattern === "fs.readFileSync")).toBe(true);
    });

    it("recognizes an unreplaced built-in constructor alias", async () => {
        const result = await scan(`
            const Factory = Array;
            const rows = Factory.from({length: process.env.COUNT}, (_, i) => i);
            fs.readFileSync('/cache/view.s' + rows[0] + '.json');
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it("does not invoke the mapper for a literal zero length", async () => {
        const result = await scan(`
            const rows = Array.from({length: 0}, () => { exec(process.env.INPUT); return process.env.INPUT; });
            exec(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it("retains unknown return alternatives beside a generated index", async () => {
        const result = await scan(`
            declare function external(): string;
            const rows = Array.from({length: process.env.INPUT}, (_, i) => flag ? i : external());
            fs.readFileSync(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("keeps unknown mapper receiver alternatives conservative", async () => {
        const result = await scan(`
            const rows = Array.from({length: process.env.COUNT}, function (_, i) {
                exec(this);
                return i;
            }, process.env.INPUT);
            fs.readFileSync(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.length).toBeGreaterThan(0);
    });

    it("preserves unknown object mapper results beside a generated-index field", async () => {
        const result = await scan(`
            declare function external(): {index: string};
            const rows = Array.from({length: process.env.INPUT}, (_, i) => flag ? {index: i} : external());
            fs.readFileSync(rows[0].index);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it("does not retain a generated scalar snapshot after a conditional unknown overwrite", async () => {
        const result = await scan(`
            declare function external(): number;
            const rows = Array.from({length: process.env.INPUT}, (_, i) => {
                if (flag) i = external();
                return i;
            });
            fs.readFileSync(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
    });

    it.each([
        ["Node global", `global.Array.from = () => [process.env.INPUT];`],
        ["browser window", `window.Array.from = () => [process.env.INPUT];`],
        ["browser self", `self.Array.from = () => [process.env.INPUT];`],
        ["Node global alias", `const root = global; root.Array.from = () => [process.env.INPUT];`],
        ["window alias", `const root = window; root.Array.from = () => [process.env.INPUT];`],
        ["self alias", `const root = self; root.Array.from = () => [process.env.INPUT];`],
        [
            "Node computed alias path",
            `const root = global; const key = 'Array'; root[key]['from'] = () => [process.env.INPUT];`,
        ],
        ["window computed path", `const key = 'Array'; window[key].from = () => [process.env.INPUT];`],
        ["self computed path", `const key = 'Array'; self[key].from = () => [process.env.INPUT];`],
    ])("retains fallback for ambient global: %s", async (_name, mutation) => {
        const result = await scan(
            `${mutation} const rows = Array.from({length: process.env.COUNT}, value => value); exec(rows[0]);`,
        );
        expect(result.skippedEntryPoints).toEqual([]);
        expect(
            result.findings.some(
                (finding) =>
                    finding.sinkLocation.text === "exec(rows[0])" &&
                    finding.propagationChain.some((step) => step.description === "accessed property 'COUNT'"),
            ),
        ).toBe(true);
    });

    it.each(["global", "window", "self"])("does not identify local %s shadows as ambient roots", async (root) => {
        const result = await scan(`
            const ${root} = {Array: {from: () => ['fixed']}};
            ${root}.Array.from = () => ['replacement'];
            const rows = Array.from({length: process.env.COUNT}, (_, i) => i);
            fs.readFileSync('/cache/view.s' + rows[0] + '.json');
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it.each([
        [
            "destructuring assignment constructor",
            `let Factory; ({constructor: Factory} = [] as any); Factory.from = () => [process.env.INPUT];`,
        ],
        [
            "computed destructuring assignment constructor",
            `let Factory; ({['constructor']: Factory} = [] as any); Factory.from = () => [process.env.INPUT];`,
        ],
        [
            "destructuring assignment prototype",
            `let Prototype; ({prototype: Prototype} = ({}).constructor); Prototype[0] = process.env.INPUT;`,
        ],
        [
            "destructured literal constructor",
            `const {constructor: Factory} = [] as any; Factory.from = () => [process.env.INPUT];`,
        ],
        [
            "constant-key constructor exposure",
            `const key = 'constructor'; const Factory = ([] as any)[key]; Factory.from = () => [process.env.INPUT];`,
        ],
        [
            "destructured literal prototype",
            `const {constructor: Factory} = {}; const {prototype: Prototype} = Factory; Prototype[0] = process.env.INPUT;`,
        ],
        ["literal Array constructor", `([] as any).constructor.from = () => [process.env.INPUT];`],
        ["literal Object constructor", `({}).constructor.prototype[0] = process.env.INPUT;`],
        [
            "literal constructor alias",
            `const Constructor = ([] as any).constructor; Constructor.from = () => [process.env.INPUT];`,
        ],
        [
            "object literal prototype field",
            `const object = {prototype: Object.prototype}; object.prototype[0] = process.env.INPUT;`,
        ],
        [
            "noninitializer prototype assignment",
            `let Prototype; Prototype = Object.prototype; Prototype[0] = process.env.INPUT;`,
        ],
        [
            "object literal constructor field",
            `const object = {Factory: Array}; object.Factory.from = () => [process.env.INPUT];`,
        ],
        [
            "shorthand constructor field",
            `const Factory = Array; const object = {Factory}; object.Factory.from = () => [process.env.INPUT];`,
        ],
        [
            "direct shorthand constructor field",
            `const object = {Array}; object.Array.from = () => [process.env.INPUT];`,
        ],
        ["mutable constructor initializer", `let Factory = Array; Factory.from = () => [process.env.INPUT];`],
        [
            "noninitializer constructor assignment",
            `let Factory; Factory = Array; Factory.from = () => [process.env.INPUT];`,
        ],
        [
            "returned constructor value",
            `function factory() { return Array; } factory().from = () => [process.env.INPUT];`,
        ],
        ["Array value stored in array", `const factories = [Array]; factories[0].from = () => [process.env.INPUT];`],
        [
            "conditional constructor value",
            `const Factory = flag ? Array : undefined; Factory!.from = () => [process.env.INPUT];`,
        ],
        [
            "computed prototype exposure",
            `const object = {}; object['constructor']['prototype'][0] = process.env.INPUT;`,
        ],
        [
            "unknown prototype property key",
            `const key = process.env.KEY; const Prototype = Object[key]; Prototype[0] = process.env.INPUT;`,
        ],
    ])("vetoes exposed built-in alternative: %s", async (_name, mutation) => {
        const result = await scan(`
            ${mutation}
            const rows = Array.from({length: process.env.COUNT}, value => value);
            exec(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        // COUNT checks fallback rather than claiming inherited pollution introduces a source.
        expect(
            result.findings.some(
                (finding) =>
                    finding.sinkLocation.text === "exec(rows[0])" &&
                    finding.propagationChain.some((step) => step.description === "accessed property 'COUNT'"),
            ),
        ).toBe(true);
    });

    it.each([
        [
            "erased interface heritage",
            `interface Rows extends Array<number> {} const rows = Array.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
        [
            "erased qualified type query",
            `type From = typeof Array.from; const rows = Array.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
        [
            "erased Array type alias",
            `type Rows = Array<number>; const rows = Array.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
        [
            "erased Array type query",
            `type ConstructorType = typeof Array; const rows = Array.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
        [
            "erased generic type argument",
            `type ConstructorType = Array<typeof Array>; const rows = Array.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
    ])("retains qualified precision with %s", async (_name, body) => {
        const result = await scan(`${body} fs.readFileSync('/cache/view.s' + rows[0] + '.json');`);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it.each([
        ["runtime class extends", `class Derived extends Array<number> {} Derived.from = () => [process.env.INPUT];`],
        [
            "runtime generic constructor value",
            `const Factory = Array<number>; const object = {Factory}; object.Factory.from = () => [process.env.INPUT];`,
        ],
    ])("retains fallback for %s exposure", async (_name, mutation) => {
        const result = await scan(
            `${mutation} const rows = Array.from({length: process.env.COUNT}, value => value); exec(rows[0]);`,
        );
        expect(result.skippedEntryPoints).toEqual([]);
        expect(
            result.findings.some(
                (finding) =>
                    finding.propagationChain.some((step) => step.description === "accessed property 'COUNT'") &&
                    finding.sinkLocation.text === "exec(rows[0])",
            ),
        ).toBe(true);
    });

    it.each([
        ["direct built-in", `const rows = Array.from({length: process.env.COUNT}, (_, i) => i);`],
        [
            "const constructor alias",
            `const Factory = Array; const rows = Factory.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
        [
            "const alias chain",
            `const Factory = Array; const Alias = Factory; const rows = Alias.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
        [
            "benign static call",
            `Object.keys({fixed: true}); const rows = Array.from({length: process.env.COUNT}, (_, i) => i);`,
        ],
    ])("qualifies clean generated indices for %s", async (_name, body) => {
        const result = await scan(`${body} fs.readFileSync('/cache/view.s' + rows[0] + '.json');`);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(0);
    });

    it.each([
        ["Object.getPrototypeOf result", `Object.getPrototypeOf({})[0] = process.env.INPUT;`],
        ["unnamed array prototype", `([] as any).__proto__[0] = process.env.INPUT;`],
        ["unnamed object prototype through array", `([] as any).__proto__.__proto__[0] = process.env.INPUT;`],
        ["Reflect.getPrototypeOf result", `Reflect.getPrototypeOf({})[0] = process.env.INPUT;`],
        ["prototype result alias", `const prototype = Object.getPrototypeOf({}); prototype[0] = process.env.INPUT;`],
        [
            "prototype accessor alias",
            `const getPrototype = Reflect.getPrototypeOf; getPrototype({})[0] = process.env.INPUT;`,
        ],
        [
            "destructured prototype accessor",
            `const {getPrototypeOf: getPrototype} = Object; getPrototype({})[0] = process.env.INPUT;`,
        ],
        ["reflected __proto__ access", `Reflect.get({}, '__proto__')[0] = process.env.INPUT;`],
        [
            "reflected accessor alias",
            `const {get: access} = Reflect; const prototype = access({}, '__proto__'); prototype[0] = process.env.INPUT;`,
        ],
        [
            "legacy prototype getter",
            `const access = Object.prototype.__lookupGetter__('__proto__'); access!.call({})[0] = process.env.INPUT;`,
        ],
        [
            "reflected descriptor getter",
            `const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf({}), '__proto__'); descriptor!.get!.call({})[0] = process.env.INPUT;`,
        ],
    ])("vetoes unnamed prototype alternative: %s", async (_name, mutation) => {
        const result = await scan(`
            ${mutation}
            const rows = Array.from({length: process.env.COUNT}, value => value);
            exec(rows[0]);
        `);
        expect(result.skippedEntryPoints).toEqual([]);
        // The length source checks conservative fallback, not inherited-property source modeling.
        expect(
            result.findings.some(
                (finding) =>
                    finding.source.pattern === "process.env" &&
                    finding.sinkLocation.text === "exec(rows[0])" &&
                    finding.propagationChain.some((step) => step.description === "accessed property 'COUNT'"),
            ),
        ).toBe(true);
    });

    it.each([
        [
            "generator mapper",
            `const rows = Array.from({length: process.env.COUNT}, function* () { yield process.env.INPUT; });
            exec(rows[0].next().value);`,
        ],
        [
            "async mapper",
            `const rows = Array.from({length: process.env.COUNT}, async (_, i) => i);
            fs.readFileSync(rows[0]);`,
        ],
        [
            "inherited indexed value",
            `Object.prototype[0] = process.env.INPUT;
            const rows = Array.from({length: process.env.COUNT}, value => value); exec(rows[0]);`,
        ],
        [
            "inherited iterator",
            `Object.prototype[Symbol.iterator] = function* () { yield process.env.INPUT; };
            const rows = Array.from({length: process.env.COUNT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "prototype alias",
            `const Prototype = Object.prototype;
            Prototype[0] = process.env.INPUT;
            const rows = Array.from({length: process.env.COUNT}, value => value); exec(rows[0]);`,
        ],
        [
            "unknown prototype escape",
            `declare function external(value: unknown): void;
            external(Object.prototype);
            const rows = Array.from({length: process.env.COUNT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "globalThis constructor override",
            `declare const replacement: typeof Array.from;
            globalThis.Array.from = replacement;
            const rows = Array.from({length: process.env.INPUT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "argument-evaluation override",
            `declare const replacement: typeof Array.from;
            function count() { Array.from = replacement; return process.env.INPUT; }
            const rows = Array.from({length: count()}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "tainted index overwrite",
            `const rows = Array.from({length: 1}, (_, i) => { i = process.env.INPUT as any; return i; });
            fs.readFileSync(rows[0]);`,
        ],
        [
            "typed shadow constructor",
            `const Factory: ArrayConstructor = {from: () => [process.env.INPUT]} as any;
            const rows = Factory.from({length: 1}, (_, i) => i); exec(rows[0]);`,
        ],
        [
            "global constructor replacement",
            `declare const replacement: ArrayConstructor;
            Array = replacement;
            const rows = Array.from({length: process.env.INPUT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "computed static override",
            `declare const replacement: typeof Array.from;
            Array['from'] = replacement;
            const rows = Array.from({length: process.env.INPUT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        ["tainted input array", `const rows = Array.from([process.env.INPUT], value => value); exec(rows[0]);`],
        [
            "indexed properties",
            `const rows = Array.from({length: 1, 0: process.env.INPUT}, value => value); exec(rows[0]);`,
        ],
        [
            "custom iterator",
            `const content = process.env.INPUT;
            const rows = Array.from({length: 1, 0: content, [Symbol.iterator]: function* () { yield this[0]; }}, value => value);
            exec(rows[0]);`,
        ],
        [
            "unknown iterator alternative",
            `declare const extra: object;
            const rows = Array.from({length: process.env.INPUT, ...extra}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "unknown mapper",
            `declare const mapper: (value: unknown, i: number) => string;
            const rows = Array.from({length: process.env.INPUT}, mapper); fs.readFileSync(rows[0]);`,
        ],
        [
            "mixed known and unknown mapper",
            `declare const mapper: (value: unknown, i: number) => string;
            const callback = flag ? (_, i) => i : mapper;
            const rows = Array.from({length: process.env.INPUT}, callback); fs.readFileSync(rows[0]);`,
        ],
        [
            "local shadow constructor",
            `const Array = {from: (input, mapper) => [process.env.INPUT]};
            const rows = Array.from({length: 1}, (_, i) => i); exec(rows[0]);`,
        ],
        [
            "shadow constructor alias",
            `const Local = {from: (input, mapper) => [process.env.INPUT]};
            const Factory = Local; const rows = Factory.from({length: 1}, (_, i) => i); exec(rows[0]);`,
        ],
        [
            "known static override",
            `Array.from = (input, mapper) => [input.length];
            const rows = Array.from({length: process.env.INPUT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "unknown static override",
            `declare const replacement: typeof Array.from;
            Array.from = replacement;
            const rows = Array.from({length: process.env.INPUT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "static override through constructor alias",
            `const Factory = Array;
            Factory.from = (input, mapper) => [input.length];
            const rows = Array.from({length: process.env.INPUT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
        [
            "mixed constructor",
            `const Factory = flag ? Array : {from: (input, mapper) => [process.env.INPUT]};
            const rows = Factory.from({length: process.env.INPUT}, (_, i) => i); fs.readFileSync(rows[0]);`,
        ],
    ])("preserves %s alternatives", async (_name, body) => {
        const result = await scan(body);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.length).toBeGreaterThan(0);
    });
});
