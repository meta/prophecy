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
            description: "Untrusted environment",
            taintAllProperties: true,
        },
    ],
    sinks: NodeSinks,
    sanitizers: [],
};

async function scan(body: string, content = false) {
    const result = await analyze({
        source: `import axios from 'axios'; import * as fs from 'node:fs'; import {exec} from 'node:child_process';
            export function main() {const input = process.env.INPUT!; ${body} }`,
        fileName: path.join(__dirname, "nodeApiCoverage-defaults-input.ts"),
        spec: { ...spec, sources: [...spec.sources, ...(content ? NodeFileSources : [])] },
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("nodeApiCoverage Axios instance defaults", () => {
    it.each([
        ["{baseURL:input}", "client.get('/run')"],
        ["{baseURL:input}", "client.request({url:'/run'})"],
        ["{baseURL:input}", "client('/run')"],
        ["{socketPath:input}", "client.post('/run', 'fixed')"],
        ["{proxy:{host:input,port:80}}", "client.get('http://fixed.test')"],
        ["{proxy:{host:'fixed.test',port:input}}", "client.get('/run')"],
    ])("uses inherited destinations %s at %s", async (defaults, request) => {
        const findings = await scan(`const client = axios.create(${defaults}); ${request};`);
        expect(findings).toHaveLength(1);
        expect(findings[0].sink.categories).toEqual(["ssrf"]);
        expect(findings[0].sinkLocation.text).toContain(request);
    });

    it.each([
        "const client = axios.create({baseURL:input});",
        "const client = axios.create({url:input}); client.request({});",
        "const client = axios.create({data:input,headers:{url:input}}); client.get('https://fixed.test');",
        "const client = axios.create({baseURL:input}); client.get('/run',{baseURL:'https://fixed.test'});",
        "const client = axios.create({socketPath:input}); client.get('/run',{socketPath:null});",
        "const client = axios.create({proxy:{host:input}}); client.get('/run',{proxy:false});",
        "const client = axios.create({proxy:{host:input}}); client.get('/run',{proxy:{host:'fixed.test'}});",
        "const client = axios.create({proxy:{auth:{username:input}}}); client.get('https://fixed.test');",
        "const defaults={baseURL:input}; const client=axios.create({...defaults,baseURL:'https://fixed.test'}); client.get('/run');",
    ])("does not turn construction, payload, or a replaced default into a request: %s", async (body) => {
        expect(await scan(body)).toEqual([]);
    });

    it("retains inherited proxy children not overwritten by the deep merge", async () => {
        const findings = await scan(`
            const client = axios.create({proxy:{host:'fixed.test',port:input}});
            client.get('/run',{proxy:{host:'other.test'}});
        `);
        expect(findings.map((f) => f.sink.categories)).toEqual([["ssrf"]]);
    });

    it("does not consume defaults or pollute other clients", async () => {
        const findings = await scan(`
            const unsafe = axios.create({baseURL:input});
            const safe = axios.create({baseURL:'https://fixed.test'});
            unsafe.get('/run',{baseURL:'https://fixed.test'});
            safe.get('/run');
            unsafe.get('/run');
            unsafe.get('/again');
        `);
        expect(findings).toHaveLength(2);
        expect(findings.every((f) => f.sinkLocation.text?.startsWith("unsafe.get"))).toBe(true);
    });

    it.each(["{baseURL:undefined}", "{baseURL:'https://fixed.test',...JSON.parse(input)}"])(
        "retains defaults when an override can be absent: %s",
        async (config) => {
            const findings = await scan(`const client = axios.create({baseURL:input}); client.get('/run',${config});`);
            expect(findings.some((f) => f.sink.categories.includes("ssrf"))).toBe(true);
        },
    );

    it("carries client defaults through helper parameters and return values", async () => {
        const findings = await scan(`
            function make(value: string) { return axios.create({baseURL:value}); }
            function dispatch(client: any) { client.get('/run'); }
            dispatch(make(input));
        `);
        expect(findings.map((f) => f.sink.categories)).toEqual([["ssrf"]]);
    });

    it("preserves defaults across imported factory and request helpers", async () => {
        const result = await analyze({
            projectDir: path.join(__dirname, "fixtures/nodeApiCoverageDefaults"),
            spec,
            outputFormat: "json",
        });
        expect(result.syntaxErrors).toEqual([]);
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sinkLocation.fileName.endsWith("helpers.ts")).toBe(true);
        expect(result.findings[0].sourceLocation.fileName.endsWith("main.ts")).toBe(true);
    });

    it("does not model unrelated local create/get implementations as Axios", async () => {
        expect(
            await scan(`
            const local = {create(options: unknown) { return {get(path: string) {}}; }};
            const client = local.create({baseURL:input}); client.get('/run');
        `),
        ).toEqual([]);
    });
});

describe("nodeApiCoverage descriptor-selected streams", () => {
    it.each(["createReadStream", "createWriteStream"])("ignores the path for a proven fd in %s", async (method) => {
        expect(
            await scan(`
            const descriptor = 3; const fd = 0;
            fs.${method}(input,{fd:0});
            fs.${method}(input,{fd:descriptor});
            fs.${method}(input,{fd});
        `),
        ).toEqual([]);
    });

    it.each(["null", "undefined", "input", "-1"])("retains the path for unproven fd %s", async (descriptor) => {
        const findings = await scan(`
            fs.createReadStream(input,{fd:${descriptor}});
            fs.createWriteStream(input,{fd:${descriptor}});
        `);
        expect(findings.map((f) => f.sink.name)).toEqual(["createReadStream_path", "createWriteStream_path"]);
    });

    it("does not trust an unknown spread or mutated options alias", async () => {
        const findings = await scan(`
            const options:any = {fd:0}; options.fd = undefined;
            fs.createReadStream(input,options);
            fs.createWriteStream(input,{fd:0,...JSON.parse(input)});
        `);
        expect(findings.map((f) => f.sink.name)).toEqual(["createReadStream_path", "createWriteStream_path"]);
    });

    it("keeps file content tainted even when a descriptor replaces the path", async () => {
        const findings = await scan(
            `
            fs.createReadStream(input,{fd:0}).on('data', chunk => exec(chunk.toString()));
        `,
            true,
        );
        expect(findings.map((f) => [f.sink.name, f.source.pattern])).toEqual([["exec", "fs.createReadStream"]]);
    });
});
