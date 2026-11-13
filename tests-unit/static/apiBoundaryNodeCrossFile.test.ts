/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import { analyze } from "../../src/static/analyzer";
import { parseProject } from "../../src/static/parser";
import { NodeSinks } from "../../src/static/spec/nodeApis";
import { TaintSpec } from "../../src/static/spec/types";
import { apiBoundaryFixture } from "./apiBoundaryFixture";

const nodeSpec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [
        { kind: "propertyAccess", pattern: "process.env", description: "Environment input", taintAllProperties: true },
    ],
    sinks: NodeSinks,
    sanitizers: [],
};
const axiosDeclarations = `
    declare const process: {env: Record<string, string>};
    declare module "axios" {
        interface AxiosInstance {get(url: string): void;}
        const axios: {create(): AxiosInstance; get(url: string): void};
        export default axios;
    }
`;

describe("Node API identities through local modules", () => {
    it.each<{ name: string; spec: TaintSpec; files: Record<string, string> }>([
        {
            name: "exported Axios client",
            spec: nodeSpec,
            files: {
                "client.ts": `import axios from "axios"; export const client = axios.create();`,
                "main.ts": `import {client} from "./client"; export function main() {client.get(process.env.INPUT);}`,
                "axios.d.ts": axiosDeclarations,
            },
        },
        {
            name: "reexported Axios callable object",
            spec: nodeSpec,
            files: {
                "client.ts": `export {default as axios} from "axios";`,
                "main.ts": `import {axios} from "./client"; export function main() {axios.get(process.env.INPUT);}`,
                "axios.d.ts": axiosDeclarations,
            },
        },
    ])("retains $name", async ({ spec, files }) => {
        const projectDir = apiBoundaryFixture(files, "");
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
});
