/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as path from "path";
import * as ts from "typescript";
import { analyze } from "../../src/static/analyzer";
import { parseProject, parseSource } from "../../src/static/parser";
import { isBuiltinCollectionCardinality } from "../../src/static/taint/nodeApiModels";
import { expressSpec } from "../../src/static/spec/express";
import { ExecFileArgsSink, ExecFileBinarySink, ExecSink, FetchSink } from "../../src/static/spec/sinks";
import { NodeFileReadSinks } from "../../src/static/spec/nodeApis";
import { TaintSpec } from "../../src/static/spec/types";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

const input = {
    kind: "callReturnValue" as const,
    pattern: "input",
    description: "external input",
    taintAllProperties: true,
};
const fetchSpec: TaintSpec = { entryFunctions: ["main"], sources: [input], sinks: [FetchSink], sanitizers: [] };

describe("HTTP fetch sink identity", () => {
    it.each([
        ["native fetch", "fetch(input());", 1],
        ["native global member", "globalThis.fetch(input());", 1],
        ["native window member", "window.fetch(input());", 1],
        ["native worker member", "self.fetch(input());", 1],
        ["captured native fetch", "const request = fetch; request(input());", 1],
        ["fixed URL", "fetch('https://example.com');", 0],
        ["local function", "const fetch = (value: string) => value; fetch(input());", 0],
        [
            "local installer method",
            "const installer = {fetch(user: string) { return user; }}; installer.fetch(input());",
            0,
        ],
        ["local imported name", "import {fetch} from './client'; fetch(input());", 0],
        ["node-fetch default", "import request from 'node-fetch'; request(input());", 1],
        ["node-fetch namespace default", "import * as client from 'node-fetch'; client.default(input());", 1],
        ["Undici named export", "import {fetch as request} from 'undici'; request(input());", 1],
        ["Undici CommonJS member", "const client = require('undici'); client.fetch(input());", 1],
        ["captured Undici member", "const {fetch: request} = require('undici'); request(input());", 1],
        ["replaced native function", "globalThis.fetch = (value: any) => value; globalThis.fetch(input());", 0],
        [
            "native global alias after replacement",
            "globalThis.fetch = (value: any) => value; window.fetch(input());",
            0,
        ],
        [
            "defined native replacement",
            "Object.defineProperty(globalThis, 'fetch', {value: (value: any) => value}); globalThis.fetch(input());",
            0,
        ],
        [
            "native alias before replacement",
            "const request = fetch; globalThis.fetch = (value: any) => value; request(input());",
            1,
        ],
    ])("models %s", async (_name, body, expected) => {
        const result = await analyze({
            source: `declare function input(): string; export function main() { ${body} }`,
            spec: fetchSpec,
            outputFormat: "json",
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.findings).toHaveLength(expected as number);
    });

    it("uses Node global declarations without the DOM library", async () => {
        const dir = apiBoundaryFixture(
            {
                "main.ts": `declare function input(): string;
                export function main() {
                    fetch(input());
                    globalThis.fetch(input());
                    global.fetch(input());
                    const request = fetch;
                    request(input());
                }`,
            },
            "",
        );
        try {
            const configPath = path.join(dir, "tsconfig.json");
            const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
            config.compilerOptions.lib = ["es2020"];
            config.compilerOptions.types = ["node"];
            config.compilerOptions.typeRoots = [path.resolve(__dirname, "../../node_modules/@types")];
            fs.writeFileSync(configPath, JSON.stringify(config));
            expect(parseProject(dir).program.getSemanticDiagnostics()).toEqual([]);
            const result = await analyze({
                projectDir: dir,
                spec: fetchSpec,
                requireTypes: true,
                outputFormat: "json",
            });
            expect(result.findings).toHaveLength(4);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

const expressDeclarations = `declare module "express" {
    export interface Request { query: Record<string, string>; body: any; }
    export interface Response {
        send(body?: any): this;
        sendStatus(status: number): this;
        status(status: number): this;
        type(contentType: string): this;
        set(header: string, value: string): this;
    }
    export interface Application {
        get(path: string, callback: (request: Request, response: Response) => void): this;
        use(callback: (request: Request, response: Response, next: () => void) => void): this;
    }
    export default function express(): Application;
}`;

describe("Express send body signature", () => {
    it.each([
        ["HTML string", "res.send('<p>' + req.query.value + '</p>');", 1],
        ["unknown request body", "res.send(req.body);", 1],
        ["serialized JSON string", "res.send(JSON.stringify({value: req.query.value}));", 1],
        ["object body", "res.send({value: req.query.value});", 0],
        ["HTML content type", "res.type('html'); res.send({value: req.query.value});", 1],
        ["HTML header", "res.set('Content-Type', 'text/html'); res.send({value: req.query.value});", 1],
        ["fluent HTML content type", "res.type('html').send({value: req.query.value});", 1],
        [
            "response handed to a helper",
            "function configure(response: any) {response.type('html');} configure(res); res.send({value: req.query.value});",
            1,
        ],
        [
            "opaque response helper",
            "function deliver(response: any, value: string) {response.send({value});} deliver(res, req.query.value);",
            1,
        ],
        [
            "status-only error branch",
            "if (!req.query.value) {res.sendStatus(404); return;} res.send({value: req.query.value});",
            0,
        ],
        ["array body", "res.send([req.query.value]);", 0],
        ["object alias", "const body = {value: req.query.value}; res.send(body);", 0],
        ["cast string", "res.send(req.query.value as unknown as {value: string});", 1],
        ["cast string alias", "const body = req.query.value as unknown as {value: string}; res.send(body);", 1],
        [
            "closed object assignments",
            "let body: {value: string}; try {body = {value: req.query.value};} catch {body = {value: req.query.value};} res.send(body);",
            0,
        ],
        [
            "typed object result",
            "function body(value: string): {value: string} {return {value};} res.send(body(req.query.value));",
            0,
        ],
        [
            "reassigned unknown alias",
            "let body: any = {value: req.query.value}; body = req.query.value; res.send(body);",
            1,
        ],
        [
            "mixed unknown shape",
            "const body: any = req.query.value ? {value: req.query.value} : req.query.value; res.send(body);",
            1,
        ],
    ])("models %s with declarations", async (_name, body, expected) => {
        const dir = apiBoundaryFixture(
            {
                "main.ts": `import express from 'express'; const app = express(); app.get('/', (req, res) => { ${body} });`,
            },
            expressDeclarations,
        );
        try {
            expect(parseProject(dir).program.getSemanticDiagnostics()).toEqual([]);
            const result = await analyze({
                projectDir: dir,
                spec: expressSpec,
                requireTypes: true,
                outputFormat: "json",
            });
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings.filter((finding) => finding.sink.name === "send")).toHaveLength(expected as number);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it.each([
        ["HTML string", "res.send(req.query.value);", 1],
        ["object body", "res.send({value: req.query.value});", 0],
        ["array body", "res.send([req.query.value]);", 0],
        ["unknown body", "res.send(req.body);", 1],
    ])("models %s without declarations", async (_name, body, expected) => {
        const dir = apiBoundaryFixture(
            {
                "main.ts": `import express from 'express'; const app = express(); app.get('/', (req, res) => { ${body} });`,
            },
            "",
        );
        try {
            const result = await analyze({ projectDir: dir, spec: expressSpec, outputFormat: "json" });
            expect(result.findings.filter((finding) => finding.sink.name === "send")).toHaveLength(expected as number);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

const htmlSpec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [input],
    sanitizers: [],
    sinks: [
        { kind: "callArgument", name: "html", pattern: "renderHtml", categories: ["xss"], description: "HTML syntax" },
    ],
};

describe("Native collection cardinality", () => {
    it("does not give a local getter the native cardinality model", () => {
        const parsed = parseSource(
            "class Values {get size() {return 'value';}} const values = new Values(); values.size;",
        );
        const last = parsed.sourceFiles[0].statements[parsed.sourceFiles[0].statements.length - 1];
        expect(ts.isExpressionStatement(last)).toBe(true);
        const expression = (last as ts.ExpressionStatement).expression as ts.PropertyAccessExpression;
        expect(isBuiltinCollectionCardinality(expression, parsed.checker)).toBe(false);
    });
    it.each([
        ["Map size", "const values = new Map([['key', input()]]); renderHtml(`${values.size}`);", 0],
        ["Set size", "const values = new Set([input()]); renderHtml(`${values.size}`);", 0],
        ["Map payload", "const values = new Map([['key', input()]]); renderHtml(values.get('key'));", 1],
        [
            "cast receiver",
            "const values = input() as unknown as Map<string, string>; renderHtml(String(values.size));",
            1,
        ],
        [
            "parsed cast receiver",
            "const values = JSON.parse(input()) as Map<string, string>; renderHtml(String(values.size));",
            1,
        ],
        [
            "parsed readonly receiver",
            "const values = JSON.parse(input()) as ReadonlyMap<string, string>; renderHtml(String(values.size));",
            1,
        ],
        [
            "unknown typed parameter",
            "function show(values: ReadonlyMap<string, string>) {renderHtml(String(values.size));} show(JSON.parse(input()));",
            1,
        ],
        [
            "mixed receiver",
            "const values = (input() ? new Map([['key', input()]]) : JSON.parse(input())) as Map<string, string>; renderHtml(String(values.size));",
            1,
        ],
        [
            "opaque receiver escape",
            "const values = new Map([['key', input()]]); mutate(values); renderHtml(String(values.size));",
            1,
        ],
        ["local size field", "const values = {size: input()}; renderHtml(`${values.size}`);", 1],
        [
            "overridden native getter",
            "const values = new Map([['key', input()]]); Object.defineProperty(values, 'size', {value: input()}); renderHtml(`${values.size}`);",
            1,
        ],
        [
            "overridden native prototype",
            "Object.defineProperty(Map.prototype, 'size', {value: input()}); const values = new Map([['key', input()]]); renderHtml(`${values.size}`);",
            1,
        ],
    ])("models %s", async (_name, body, expected) => {
        const result = await analyze({
            source: `declare function input(): string; declare function renderHtml(value: unknown): void; declare function mutate(value: Map<string, string>): void; export function main() { ${body} }`,
            spec: htmlSpec,
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(expected as number);
    });

    it("retains cardinality provenance for input-dependent file selection", async () => {
        const result = await analyze({
            source: `import {readFileSync} from 'fs'; declare function input(): string;
                export function main() {const values = new Map([[input(), 'value']]); readFileSync(String(values.size));}`,
            spec: { ...htmlSpec, sinks: NodeFileReadSinks },
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.categories).toEqual(["file_access"]);
    });

    it("retains cardinality provenance for executable and argv selection", async () => {
        const result = await analyze({
            source: `import {execFile} from 'child_process'; declare function input(): string;
                export function main() {
                    const values = new Map([[input(), 'value'], ['fixed', 'value']]);
                    execFile(String(values.size), []);
                    execFile('program', [String(values.size)]);
                }`,
            spec: { ...htmlSpec, sinks: [ExecFileBinarySink, ExecFileArgsSink] },
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(2);
        expect(result.findings.map((finding) => finding.sink.categories[0]).sort()).toEqual(["arg_injection", "rce"]);
    });
});

describe("Context-specific encoders remain conservative", () => {
    it("retains nested field provenance through native JSON serialization", async () => {
        const result = await analyze({
            source: `declare function input(): string; declare function renderHtml(value: unknown): void; export function main() {renderHtml(JSON.stringify({value: input()}));}`,
            spec: htmlSpec,
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(1);
    });
    it.each([
        [
            "custom HTML escaping",
            "function escapeHtml(value: string) {return value.replace(/</g, '&lt;').replace(/>/g, '&gt;');} renderHtml(escapeHtml(input()));",
        ],
        [
            "script-data escaping",
            "const value = JSON.stringify({value: input()}).replace(/</g, '\\\\u003c'); renderHtml('<script>const data=' + value + '</script>');",
        ],
        [
            "decoded escaped JSON",
            "const value = JSON.stringify({value: input()}).replace(/</g, '\\\\u003c'); renderHtml(JSON.parse(value).value);",
        ],
    ])("retains %s without an encoder-context proof", async (_name, body) => {
        const result = await analyze({
            source: `declare function input(): string; declare function renderHtml(value: unknown): void; export function main() {${body}}`,
            spec: htmlSpec,
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(1);
    });

    it("retains a custom POSIX quote helper without granting universal sanitizer credit", async () => {
        const result = await analyze({
            source: `import {exec} from 'child_process'; declare function input(): string;
                function quote(value: string) {return "'" + value.replace(/'/g, "'\\\\''") + "'";}
                export function main() {exec('program --value ' + quote(input()));}`,
            spec: { ...htmlSpec, sinks: [ExecSink] },
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].sink.categories).toEqual(["rce"]);
    });
});

describe("Express response context uncertainty", () => {
    it.each([
        {
            name: "earlier middleware",
            files: {
                "main.ts": `import express from 'express'; const app = express();
            app.use((_req, res, next) => {res.type('html'); next();});
            app.get('/', (req, res) => {res.send({value: req.query.value});});`,
            },
        },
        {
            name: "imported application",
            files: {
                "server.ts": `import express from 'express'; export const app = express(); app.use((_req, res, next) => {res.type('html'); next();});`,
                "main.ts": `import {app} from './server'; app.get('/', (req, res) => {res.send({value: req.query.value});});`,
            },
        },
        {
            name: "imported application factory",
            files: {
                "server.ts": `import express from 'express'; export function createApp() {const app = express(); app.use((_req, res, next) => {res.type('html'); next();}); return app;}`,
                "main.ts": `import {createApp} from './server'; const app = createApp(); app.get('/', (req, res) => {res.send({value: req.query.value});});`,
            },
        },
        {
            name: "captured response helper",
            files: {
                "main.ts": `import express from 'express'; const app = express(); app.get('/', (req, res) => {function configure() {res.type('html');} configure(); res.send({value: req.query.value});});`,
            },
        },
    ])("retains $name", async ({ files }) => {
        const dir = apiBoundaryFixture(files, expressDeclarations);
        try {
            expect(parseProject(dir).program.getSemanticDiagnostics()).toEqual([]);
            const result = await analyze({
                projectDir: dir,
                spec: expressSpec,
                requireTypes: true,
                outputFormat: "json",
            });
            expect(result.findings.filter((finding) => finding.sink.name === "send")).toHaveLength(1);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
