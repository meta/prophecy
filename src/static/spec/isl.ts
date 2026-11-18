/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SinkSpec, TaintSpec } from "./types";
import { vscodeExtensionSpec } from "./vscodeExtension";

/**
 * Sinks for Interactive Smartlog (ISL), Sapling's web UI: its VS Code
 * extension and the Node.js server that wraps the `sl` CLI.
 *
 * Every Sapling command runs through one `spawn` call in `shared/ejeca.ts`,
 * and findings are deduplicated per sink line and entry point, so the shared
 * `spawn` sinks alone collapse all client-message flows into one finding.
 * These sinks fire at the ISL call sites instead, one finding per site.
 */
export const IslSinks: SinkSpec[] = [
    {
        kind: "callArgument",
        name: "isl_ejeca",
        pattern: "ejeca",
        argPositions: [0],
        description: "Executable chosen by tainted data in ejeca()",
        severity: "critical",
        categories: ["rce"],
    },
    {
        kind: "callArgument",
        name: "isl_ejeca_args",
        pattern: "ejeca",
        argPositions: [1],
        description: "Tainted argv passed to ejeca()",
        severity: "high",
        categories: ["arg_injection"],
    },
    {
        // `runCommand(ctx, args)` in isl-server/src/commands.ts. The shape check
        // skips `Repository.runCommand(args, eventName, ...)`, whose second
        // argument is an event name.
        kind: "callArgument",
        name: "isl_runCommand",
        pattern: "runCommand",
        argPositions: [1],
        argumentShapes: { 1: "array" },
        description: "Tainted args passed to runCommand(ctx, args)",
        severity: "high",
        categories: ["arg_injection"],
    },
    {
        kind: "callArgument",
        name: "isl_repo_runCommand",
        pattern: "Repository.runCommand",
        argPositions: [0],
        description: "Tainted args passed to Repository.runCommand()",
        severity: "high",
        categories: ["arg_injection"],
    },
    {
        kind: "callArgument",
        name: "isl_runOrQueueOperation",
        pattern: "runOrQueueOperation",
        argPositions: [1],
        description: "Client-supplied operation passed to runOrQueueOperation(); check normalizeOperationArgs",
        severity: "high",
        categories: ["arg_injection"],
    },
    {
        // The Sapling executable every repository command runs. A workspace
        // setting reaches it in a few calls, but the spawn is too deep to reach.
        kind: "callArgument",
        name: "isl_repository_cmd",
        pattern: "RepositoryCache.getOrCreate",
        argPositions: [0],
        objectProperties: ["cmd"],
        description: "Sapling executable (RepositoryContext.cmd) chosen by tainted data",
        severity: "critical",
        categories: ["rce"],
    },
    {
        kind: "callArgument",
        name: "fs_readFile_path",
        pattern: "fs.readFile",
        argPositions: [0],
        description: "Tainted path read with fs.readFile",
        severity: "medium",
        categories: ["lfi"],
    },
    ...["rm", "unlink", "rmdir"].map((api): SinkSpec => ({
        kind: "callArgument",
        name: `fs_${api}_path`,
        pattern: `fs.${api}`,
        argPositions: [0],
        description: `Tainted path deleted with fs.${api}`,
        severity: "high",
        categories: ["file_write"],
    })),
];

/** `package.json` names of the ISL VS Code extension and server, which `--rules auto` maps to {@link islSpec}. */
export const ISL_PACKAGE_NAMES: ReadonlyArray<string> = ["sapling-scm", "isl-server"];

/** The VS Code extension spec plus {@link IslSinks}. */
export const islSpec: TaintSpec = {
    ...vscodeExtensionSpec,
    sinks: [...vscodeExtensionSpec.sinks, ...IslSinks],
};
