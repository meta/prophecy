/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { FetchSink } from "../../src/static/spec/sinks";
import { TaintSpec } from "../../src/static/spec/types";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

const spec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [{ kind: "callReturnValue", pattern: "input", description: "external input", taintAllProperties: true }],
    sinks: [FetchSink],
    sanitizers: [],
};

const declarations = `declare function input(): string;
declare module "node-fetch" {
    export class Request {constructor(value: string | Request); url: string;}
    export class Response {constructor(body?: string); status: number;}
    export type RequestInfo = string | Request;
    export type RequestInit = {method?: string; body?: string};
    export default function fetch(request: RequestInfo, init?: RequestInit): Promise<Response>;
}`;

const prefix = `import nodeFetch, {Request, Response, RequestInfo, RequestInit} from 'node-fetch';
type Fetch = (request: RequestInfo, init?: RequestInit) => Promise<Response>;
function wrap(client: Fetch): Fetch {return (request, init) => client(request, init);}
async function getClient(): Promise<Fetch> {return wrap(nodeFetch);}`;

describe("HTTP fetch callable contracts", () => {
    it.each([
        [
            "awaited factory URL",
            `${prefix} export async function main() {const request = await getClient(); await request(input());}`,
            1,
        ],
        [
            "awaited factory Request URL",
            `${prefix} export async function main() {const request = await getClient(); await request(new Request(input()));}`,
            1,
        ],
        [
            "settings function field",
            `${prefix} export async function main() {const settings: {fetch: Fetch} = {fetch: await getClient()}; await settings.fetch(input());}`,
            1,
        ],
        [
            "captured settings field",
            `${prefix} export async function main() {const settings: {fetch: Fetch} = {fetch: await getClient()}; const request = settings.fetch; await request(input());}`,
            1,
        ],
        [
            "function parameter",
            `${prefix} function send(request: Fetch, url: string) {return request(url);} export async function main() {await send(nodeFetch, input());}`,
            1,
        ],
        [
            "fixed factory URL",
            `${prefix} export async function main() {const request = await getClient(); await request('https://example.com');}`,
            0,
        ],
        [
            "local installer method",
            `const installer = {async fetch(user: string, flavor: string, version: string) {return user;}}; export async function main() {await installer.fetch(input(), 'demo', 'current');}`,
            0,
        ],
        [
            "local history method",
            `const history = {fetch(id: string, mode: string) {return id;}}; export function main() {history.fetch(input(), 'full');}`,
            0,
        ],
        [
            "unrelated async function",
            `async function fetch(value: string) {return value;} export async function main() {await fetch(input());}`,
            0,
        ],
        [
            "unrelated response class",
            `class LocalResponse {constructor(public body: string){}} async function fetch(value: string) {return new LocalResponse(value);} export async function main() {await fetch(input());}`,
            0,
        ],
        [
            "type-compatible mock remains conservative",
            `${prefix} const request: Fetch = async value => new Response(String(value)); export async function main() {await request(input());}`,
            1,
        ],
    ])("models %s", async (_name, source, expected) => {
        const dir = apiBoundaryFixture({ "main.ts": source as string }, declarations);
        try {
            expect(parseProject(dir).program.getSemanticDiagnostics()).toEqual([]);
            const result = await analyze({ projectDir: dir, spec, requireTypes: true, outputFormat: "json" });
            expect(result.syntaxErrors).toEqual([]);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.findings.some((finding) => finding.sinkLocation.fileName.endsWith("main.ts"))).toBe(
                (expected as number) > 0,
            );
            if (expected === 0) expect(result.findings).toHaveLength(0);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
