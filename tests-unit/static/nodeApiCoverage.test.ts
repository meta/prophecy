/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { NodeSinks, NodeFileSources } from "../../src/static/spec/nodeApis";
import { TaintSpec } from "../../src/static/spec/types";

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [
        {
            kind: "propertyAccess",
            pattern: "process.env",
            description: "Untrusted environment input",
            taintAllProperties: true,
        },
    ],
    sinks: NodeSinks,
    sanitizers: [],
};

async function scan(source: string, fileSources = false, typed = true) {
    const result = await analyze({
        source,
        fileName: typed ? path.join(__dirname, "nodeApiCoverage-input.ts") : "/no-types/nodeApiCoverage-input.ts",
        spec: { ...spec, sources: [...spec.sources, ...(fileSources ? NodeFileSources : [])] },
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

function body(imports: string, statements: string) {
    return `${imports}\nexport async function main() { const input = process.env.INPUT!; ${statements} }`;
}

const wrappers = [
    ['import run from "execa";', "run", "execa"],
    ['import run from "execa";', "run.sync", "execa_sync"],
    ['import {execa as run} from "execa";', "run", "execa_named"],
    ['import {execaSync as run} from "execa";', "run", "execa_named_sync"],
    ['import run from "cross-spawn";', "run", "cross_spawn"],
    ['import {spawn as run} from "cross-spawn";', "run", "cross_spawn_spawn"],
    ['import run from "cross-spawn";', "run.sync", "cross_spawn_sync"],
];

describe("nodeApiCoverage process wrappers", () => {
    it.each(wrappers)("splits executable, argv, and options: %s %s", async (imports, run, name) => {
        const findings = await scan(
            body(
                imports,
                `
            ${run}(input);
            ${run}("git", [input]);
            ${run}("git", {env: {NODE_OPTIONS: input}});
            ${run}("git", [], {shell: input});
            ${run}("git", [], {input});
            ${run}("git", {env: {LOG_DIR: input}});
            ${run}("git", ["status"]);
        `,
            ),
        );
        expect(findings.map((f) => [f.sink.name, f.sink.categories])).toEqual([
            [name, ["rce"]],
            [`${name}_args`, ["arg_injection"]],
            [`${name}_options`, ["rce"]],
            [`${name}_options`, ["rce"]],
        ]);
    });

    it.each([
        ['"git", [input], {shell: true}', "rce"],
        ['"git", [input], {shell: false}', "arg_injection"],
        ['"sh", ["-c", input]', "rce"],
        ['"sh", ["-c", "printf %s \\"$1\\"", "sh", input]', "arg_injection"],
        ['"node", ["--eval", input]', "rce"],
        ['"node", ["fixed.js", input]', "arg_injection"],
    ])("classifies executable operands rather than all interpreter arguments: %s", async (args, category) => {
        const findings = await scan(body('import run from "execa";', `run(${args});`));
        expect(findings.map((f) => f.sink.categories)).toEqual([[category]]);
    });

    it("does not execute a modern Execa options-binding call", async () => {
        const findings = await scan(
            body(
                'import {execa} from "execa";',
                `
            const runner = execa({env: {NODE_OPTIONS: input}});
        `,
            ),
        );
        expect(findings).toEqual([]);
    });

    it.each([true, false])("recognizes CommonJS and import-equals aliases (typed=%s)", async (typed) => {
        const findings = await scan(
            body(
                `
            import legacy = require("execa");
            const {execa: run} = require("execa");
            const launch = require("cross-spawn");
        `,
                `legacy(input); run(input); launch(input);`,
            ),
            false,
            typed,
        );
        expect(findings.map((f) => f.sink.name).sort()).toEqual(["cross_spawn", "execa", "execa_named"]);
    });

    it("rejects unrelated local wrapper names, including namespace-shaped members", async () => {
        const findings = await scan(
            body(
                `
            function execa(value: unknown) {}
            const launch = {sync(value: unknown) {}};
            namespace local { export function execa(value: unknown) {} }
        `,
                `execa(input); launch.sync(input); local.execa(input);`,
            ),
        );
        expect(findings).toEqual([]);
    });
});

describe("nodeApiCoverage Axios destinations", () => {
    it.each([
        ["axios(input)", "axios"],
        ["axios({url: input, data: 'fixed'})", "axios"],
        ["axios({baseURL: input, url: '/path'})", "axios"],
        ["axios('/path', {baseURL: input})", "axios_config"],
        ["axios.request({url: input})", "axios_request"],
        ["axios.request(input)", "axios_request"],
        ["axios.get(input)", "axios_get"],
        ["axios.delete(input)", "axios_delete"],
        ["axios.head(input)", "axios_head"],
        ["axios.options(input)", "axios_options"],
        ["axios.post(input, 'fixed')", "axios_post"],
        ["axios.put('/path', 'fixed', {baseURL: input})", "axios_put_config"],
        ["axios.patch('/path', 'fixed', {socketPath: input})", "axios_patch_config"],
        ["axios.postForm(input, {})", "axios_postForm"],
        ["axios.putForm(input, {})", "axios_putForm"],
        ["axios.patchForm(input, {})", "axios_patchForm"],
        ["axios({url: '/path', proxy: {host: input, port: 80}})", "axios"],
    ])("reports the destination of %s", async (call, name) => {
        const findings = await scan(body('import axios from "axios";', `${call};`));
        expect(findings.map((f) => [f.sink.name, f.sink.categories])).toEqual([[name, ["ssrf"]]]);
    });

    it.each([
        "axios({url: 'https://fixed.test', data: input})",
        "axios({url: 'https://fixed.test', data: {url: input}})",
        "axios({url: 'https://fixed.test', headers: {url: input}})",
        "axios({url: 'https://fixed.test', params: {url: input}})",
        "axios({url: 'https://fixed.test', proxy: {host: 'fixed.test', auth: {username: input}}})",
        "axios.post('https://fixed.test', input)",
        "axios.put('https://fixed.test', {url: input})",
        "axios.patchForm('https://fixed.test', input, {headers: {Authorization: input}})",
        "axios.get('https://fixed.test', {url: input})",
        "axios('https://fixed.test', {url: input, data: input})",
        "axios.request('https://fixed.test', {url: input})",
    ])("does not confuse payload or an overridden URL with destination: %s", async (call) => {
        expect(await scan(body('import axios from "axios";', `${call};`))).toEqual([]);
    });

    it("conservatively retains baseURL when absolute-URL policy is not modeled", async () => {
        const findings = await scan(
            body(
                'import axios from "axios";',
                `
            axios('https://fixed.test', {baseURL: input});
        `,
            ),
        );
        // Default Axios behavior ignores this baseURL. Instance defaults can set
        // allowAbsoluteUrls:false; these models do not prove that setting's value.
        expect(findings.map((f) => f.sink.name)).toEqual(["axios_config"]);
    });

    it("tracks destination config through a helper but not payload config", async () => {
        const findings = await scan(`import axios from "axios";
            function send(config: any) { axios.request(config); }
            export function main() {
                send({url: process.env.INPUT});
                send({url: 'https://fixed.test', data: process.env.INPUT});
            }
        `);
        expect(findings.map((f) => f.sink.name)).toEqual(["axios_request"]);
    });

    it("recognizes request destinations on an Axios-created instance", async () => {
        const findings = await scan(
            body(
                'import axios from "axios";',
                `
            const client = axios.create({baseURL: 'https://fixed.test'});
            client.get(input);
            client.request({url: input});
            client.post('/fixed', input);
        `,
            ),
        );
        expect(findings.map((f) => f.sink.name)).toEqual(["axios_get", "axios_request"]);
    });

    it("recognizes an aliased CommonJS Axios import", async () => {
        const findings = await scan(body(`const client = require('axios');`, `client.post(input, 'fixed');`));
        expect(findings.map((f) => f.sink.name)).toEqual(["axios_post"]);
    });

    it("rejects local axios and same-named methods", async () => {
        expect(
            await scan(
                body(
                    `
            function axios(value: unknown) {}
            const client = {get(value: unknown) {}, request(value: unknown) {}};
        `,
                    `axios(input); client.get(input); client.request({url: input});`,
                ),
            ),
        ).toEqual([]);
    });
});

describe("nodeApiCoverage file paths and contents", () => {
    it.each(["readFile", "readFileSync", "createReadStream", "appendFile", "appendFileSync", "createWriteStream"])(
        "reports only the path of fs.%s",
        async (method) => {
            const args =
                method === "appendFile"
                    ? "input, 'fixed', () => {}"
                    : method === "appendFileSync"
                      ? "input, 'fixed'"
                      : method === "readFile"
                        ? "input, () => {}"
                        : "input";
            const findings = await scan(body('import * as fs from "node:fs";', `fs.${method}(${args});`));
            expect(findings.map((f) => [f.sink.name, f.sink.categories])).toEqual([
                [
                    `${method}_path`,
                    [method.startsWith("read") || method === "createReadStream" ? "file_access" : "file_write"],
                ],
            ]);
        },
    );

    it("reports append content separately and preserves existing write sinks", async () => {
        const findings = await scan(
            body(
                'import * as fs from "fs";',
                `
            fs.appendFile('/fixed', input, () => {});
            fs.appendFileSync('/fixed', input);
            fs.writeFile(input, input, () => {});
        `,
            ),
        );
        expect(findings.map((f) => f.sink.name)).toEqual([
            "appendFile",
            "appendFileSync",
            "writeFile_path",
            "writeFile",
        ]);
    });

    it.each(["fs/promises", "node:fs/promises"])("recognizes %s path sinks", async (module) => {
        const findings = await scan(
            body(
                `import {readFile as read, appendFile as append} from '${module}';`,
                `
            await read(input); await append(input, 'fixed');
        `,
            ),
        );
        expect(findings.map((f) => f.sink.name)).toEqual(["readFile_path", "appendFile_path"]);
    });

    it("keeps constant paths and unrelated local readFile APIs clean", async () => {
        expect(
            await scan(
                body(
                    `
            import {createReadStream, createWriteStream} from 'node:fs';
            function readFile(path: unknown, cb?: any) { return 'safe'; }
            const fs = {readFileSync(path: unknown) {return 'safe'}};
        `,
                    `readFile(input); fs.readFileSync(input); createReadStream('/fixed'); createWriteStream('/fixed');`,
                ),
            ),
        ).toEqual([]);
    });

    it("distinguishes content sources from clean read paths", async () => {
        const findings = await scan(
            body(
                `import * as fs from 'node:fs'; import {exec} from 'node:child_process';`,
                `
            exec(fs.readFileSync('/fixed', 'utf8'));
            fs.readFile('/fixed', (error, data) => exec(data.toString()));
            fs.readFile('/fixed', 'utf8', (error, data) => exec(data));
        `,
            ),
            true,
        );
        expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([
            ["exec", "fs.readFileSync"],
            ["exec", "fs.readFile.data"],
            ["exec", "fs.readFile.data"],
        ]);
    });

    it("does not taint callback return values, errors, or unrelated local reads", async () => {
        const findings = await scan(
            body(
                `import * as fs from 'node:fs'; import {exec} from 'node:child_process';`,
                `
            const result = fs.readFile('/fixed', (error, data) => exec(error));
            exec(result);
            function readFileSync(path: string) { return 'fixed'; }
            function readFile(path: string, callback: (error: unknown, data: string) => void) {
                callback(null, 'fixed');
            }
            exec(readFileSync('/fixed'));
            readFile('/fixed', (error, data) => exec(data));
        `,
            ),
            true,
        );
        expect(findings).toEqual([]);
    });

    it.each(["fs/promises", "node:fs/promises"])("reads promise content through await and then: %s", async (module) => {
        const findings = await scan(
            body(
                `import {readFile} from '${module}'; import {exec} from 'node:child_process';`,
                `
            exec(await readFile('/fixed', 'utf8'));
            readFile('/fixed', 'utf8').then(value => exec(value));
        `,
            ),
            true,
        );
        expect(findings.map((f) => f.sink.name)).toEqual(["exec", "exec"]);
        expect(findings.every((f) => f.source.pattern === "fs.readFile")).toBe(true);
    });

    it("reads promisified callback content without tainting a void return", async () => {
        const findings = await scan(
            body(
                `
            import {readFile} from 'node:fs';
            import {promisify} from 'node:util';
            import {exec} from 'node:child_process';
            const read = promisify(readFile);
        `,
                `exec(await read('/fixed', 'utf8'));`,
            ),
            true,
        );
        expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([["exec", "fs.readFile"]]);
    });

    it("sources stream chunks, not handle metadata, open events, or local emitters", async () => {
        const findings = await scan(
            body(
                `
            import {createReadStream} from 'node:fs';
            import {exec} from 'node:child_process';
        `,
                `
            const stream = createReadStream('/fixed');
            stream.on('data', chunk => exec(chunk.toString()));
            stream.once('data', chunk => exec(chunk.toString()));
            stream.addListener('data', chunk => exec(chunk.toString()));
            stream.on('open', fd => exec(fd));
            exec(stream.path);
            exec(stream);
            const local = {on(event: string, handler: any) {}};
            local.on('data', chunk => exec(chunk));
        `,
            ),
            true,
        );
        expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([
            ["exec", "fs.createReadStream"],
            ["exec", "fs.createReadStream"],
            ["exec", "fs.createReadStream"],
        ]);
    });

    it("tracks Node models across files and preserves library imports", async () => {
        const result = await analyze({
            projectDir: path.join(__dirname, "fixtures/nodeApiCoverage"),
            spec,
            outputFormat: "json",
        });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings.map((f) => f.sink.name).sort()).toEqual([
            "axios_request",
            "execa_args",
            "readFile_path",
        ]);
        expect(
            result.findings.every((f) => f.propagationChain.some((step) => step.location.fileName.endsWith("main.ts"))),
        ).toBe(true);
        expect(result.findings.every((f) => f.sinkLocation.fileName.endsWith("helpers.ts"))).toBe(true);
    });
});
