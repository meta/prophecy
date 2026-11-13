/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { NodeFileSources } from "../../src/static/spec/nodeApis";
import { ExecSink } from "../../src/static/spec/sinks";

async function scan(imports: string, body: string, typed: boolean) {
    const source = `${typed ? '/// <reference path="./fixtures/nodeApiCoverageReadVariants/fs-extra.d.ts" />' : ""}
        import {exec} from 'node:child_process';
        ${imports}
        export async function main(moduleName: string, options: unknown) { ${body} }
    `;
    const result = await analyze({
        source,
        fileName: typed
            ? path.join(__dirname, "nodeApiCoverageReadVariants-input.ts")
            : "/no-types/nodeApiCoverageReadVariants-input.ts",
        spec: { entryFunctions: ["main"], sources: NodeFileSources, sinks: [ExecSink], sanitizers: [] },
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

for (const typed of [true, false]) {
    describe(`nodeApiCoverage read variants (types=${typed})`, () => {
        it.each([
            ['import * as extra from "fs-extra";', 'exec(await extra.readFile("/fixed"));'],
            ['import * as extra from "fs-extra";', 'exec(await extra.readFile("/fixed", "utf8"));'],
            ['import {readFile as read} from "fs-extra";', 'exec(await read("/fixed", {encoding:"utf8"}));'],
            ['import * as extra from "fs-extra";', 'extra.readFile("/fixed", "utf8").then(data => exec(data));'],
            ['import * as extra from "fs-extra";', 'exec(await extra.promises.readFile("/fixed", "utf8"));'],
            ["", 'const fs=await import("fs"); exec(await fs.promises.readFile("/fixed", "utf8"));'],
            [
                "",
                'const modulePromise=import("node:fs"); const fs=await modulePromise; exec(await fs.promises.readFile("/fixed", "utf8"));',
            ],
        ])("retains promise file content: %s %s", async (imports, body) => {
            const findings = await scan(imports, body, typed);
            expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([["exec", "fs.readFile"]]);
        });

        it("retains fs-extra callback content without tainting its void return", async () => {
            const findings = await scan(
                'import * as extra from "fs-extra";',
                `
                const result = extra.readFile('/fixed', 'utf8', (error, data) => exec(data));
                exec(result);
            `,
                typed,
            );
            expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([["exec", "fs.readFile.data"]]);
        });

        it.each([
            [
                'import * as extra from "fs-extra";',
                `const result=extra.readFile('/fixed', (error,data) => {}); exec(result);`,
            ],
            [
                'import * as extra from "fs-extra";',
                `
                function callback(error:unknown,data:unknown) {}
                const result=extra.readFile('/fixed',callback); exec(result);
                const opaque=extra.readFile('/fixed',options as any); exec(opaque);
                const spread=extra.readFile(...(['/fixed',callback] as const)); exec(spread);
            `,
            ],
            ["", `const fs=await import('fs'); const result=fs.readFile('/fixed', (error,data) => {}); exec(result);`],
            [
                "",
                `const fs=await import('not-fs'); exec(await fs.readFile('/fixed')); exec(await fs.promises.readFile('/fixed'));`,
            ],
            [
                "",
                `const fs=await import(moduleName); exec(await fs.readFile('/fixed')); exec(await fs.promises.readFile('/fixed'));`,
            ],
        ])("does not invent callback returns or dynamic-import sources: %s %s", async (imports, body) => {
            expect(await scan(imports, body, typed)).toEqual([]);
        });
    });
}
