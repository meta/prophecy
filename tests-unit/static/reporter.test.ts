/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { formatFindings } from "../../src/static/reporter";
import { TaintFinding } from "../../src/static/spec/types";

const REV = "5d649c81f73b163479b45837e97e3623b3bd6548";

function makeFinding(fileName: string): TaintFinding {
    return {
        handle: "test-handle",
        sinkSite: "activate>call:exec#0",
        source: {
            kind: "propertyAccess",
            pattern: "uri.query",
            description: "URI query",
        },
        sourceLocation: {
            fileName,
            line: 10,
            column: 5,
            text: "uri.query",
        },
        sink: {
            kind: "callArgument",
            name: "exec",
            pattern: "child_process.exec",
            description: "Command execution",
            severity: "critical",
            categories: ["rce"],
        },
        sinkLocation: {
            fileName,
            line: 12,
            column: 9,
            text: "exec(command)",
        },
        propagationChain: [
            {
                kind: "assignment",
                location: {
                    fileName,
                    line: 11,
                    column: 7,
                    text: "command = uri.query",
                },
                description: "assigned to 'command'",
            },
        ],
    };
}

describe("reporter code links", () => {
    it("keeps file paths when no code link is available", () => {
        const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-local-"));
        const fileName = path.join(repoRoot, "src/extension.ts");

        const output = formatFindings([makeFinding(fileName)], repoRoot, REV);

        expect(output).toContain(`${fileName}:10:5`);
        expect(output).not.toContain("https://");

        fs.rmSync(repoRoot, { recursive: true, force: true });
    });
});
