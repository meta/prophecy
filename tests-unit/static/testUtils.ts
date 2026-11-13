/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as path from "path";
import { analyze, AnalyzerOptions, AnalyzerResult } from "../../src/static/analyzer";
import { TaintSpec } from "../../src/static/spec/types";
import { vscodeExtensionSpec } from "../../src/static/spec/vscodeExtension";

export const FIXTURES = path.join(__dirname, "fixtures");

/**
 * The VS Code spec plus `process.env` as a source. The shipped spec does not
 * treat the environment as attacker-controlled, but engine tests use it as a
 * scalar read that needs no entry-point parameter, and it is the only
 * `propertyAccess` source with `taintAllProperties`.
 */
export const vscodeSpecWithEnvSource: TaintSpec = {
    ...vscodeExtensionSpec,
    sources: [
        ...vscodeExtensionSpec.sources,
        {
            kind: "propertyAccess",
            pattern: "process.env",
            resolvedPattern: "NodeJS.Process.env",
            description: "Environment variable",
            taintAllProperties: true,
        },
    ],
};

export function analyzeFixture(
    name: string,
    options: Partial<Omit<AnalyzerOptions, "projectDir">> = {},
): Promise<AnalyzerResult> {
    return analyze({
        projectDir: path.join(FIXTURES, name),
        spec: vscodeExtensionSpec,
        maxDepth: 5,
        outputFormat: "text",
        ...options,
    });
}
