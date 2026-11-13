/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { expressSpec } from "../../src/static/spec/express";
import { TaintSpec } from "../../src/static/spec/types";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

// Minimal public Express contracts; no framework implementation is installed.
// https://expressjs.com/en/4x/api.html
const declarations = `
declare module "child_process" { export function exec(command: string): void; }
declare module "express" {
    export interface Request {
        body: any;
        query: Record<string, string>;
    }
    export interface Response {statusCode: number;}
    export type Handler = (request: Request, response: Response, next: () => void) => any;
    export interface Application {
        get(path: string, ...handlers: Handler[]): this;
        post(path: string, ...handlers: Handler[]): this;
        use(...handlers: Handler[]): this;
    }
    export default function express(): Application;
}`;

describe("Express API identities through local modules", () => {
    it.each<{ name: string; spec: TaintSpec; files: Record<string, string> }>([
        {
            name: "exported Express instance",
            spec: expressSpec,
            files: {
                "server.ts": `import express from "express"; export const app = express();`,
                "main.ts": `import {app} from "./server"; import {exec} from "child_process";
                    app.post("/run", request => exec(request.body.command));`,
            },
        },
        {
            name: "default-exported Express instance",
            spec: expressSpec,
            files: {
                "server.ts": `import express from "express"; export default express();`,
                "main.ts": `import app from "./server"; import {exec} from "child_process";
                    app.post("/run", request => exec(request.query.command));`,
            },
        },
    ])("retains $name", async ({ spec, files }) => {
        const projectDir = apiBoundaryFixture(files, declarations);
        try {
            const { program } = parseProject(projectDir);
            expect(program.getSemanticDiagnostics()).toEqual([]);
            const result = await analyze({ projectDir, spec, outputFormat: "json", maxDepth: 8, requireTypes: true });
            expect(result.syntaxErrors).toEqual([]);
            expect(result.skippedEntryPoints).toEqual([]);
            expect(result.entryPointCount).toBe(1);
            expect(result.findings).toHaveLength(1);
        } finally {
            fs.rmSync(projectDir, { recursive: true, force: true });
        }
    });

    it("does not turn a reexported local lookalike into an API", async () => {
        const projectDir = apiBoundaryFixture(
            {
                "server.ts": `export const app = {post(path: string, handler: (request: any) => void) {}};`,
                "main.ts": `import {app} from "./server"; import {exec} from "child_process";
                app.post("/run", request => exec(request.body.command));`,
            },
            declarations,
        );
        try {
            const { program } = parseProject(projectDir);
            expect(program.getSemanticDiagnostics()).toEqual([]);
            const result = await analyze({ projectDir, spec: expressSpec, outputFormat: "json", requireTypes: true });
            expect(result.findings).toHaveLength(0);
            expect(result.entryPointCount).toBe(0);
        } finally {
            fs.rmSync(projectDir, { recursive: true, force: true });
        }
    });
});
