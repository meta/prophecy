/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { HttpRequestPropertyPaths } from "./http";
import { SinkSpec, SourceSpec, TaintSpec } from "./types";
import { vscodeExtensionSpec } from "./vscodeExtension";

/** Inputs to ISL's server besides the client messages the VS Code spec already models. */
export const IslSources: SourceSpec[] = [
    {
        // Every repository command runs through `ejeca`, so its output carries
        // file names, commit text, bookmark names and configuration values.
        kind: "callReturnValue",
        pattern: "ejeca",
        description: "Output of a command run through ejeca() (repository-controlled in an untrusted checkout)",
        taintAllProperties: true,
    },
    ...["on", "once", "addListener"].map((method): SourceSpec => ({
        // The standalone server reads its starting directory and platform from
        // the URL of the WebSocket upgrade request.
        kind: "parameter",
        pattern: `ws.WebSocketServer.${method}.request`,
        description: "WebSocket upgrade request (URL and headers chosen by the connecting client)",
        callbackRegistration: `ws.WebSocketServer.${method}`,
        callbackMatch: "api",
        callbackArgumentValues: { 0: ["connection"] },
        callbackArgIndex: 1,
        paramIndex: 1,
        paramPropertyPaths: HttpRequestPropertyPaths,
        taintAllProperties: true,
        entryPointDescription: "WebSocket connection handler",
    })),
];

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
    // An operation names its runner, and only the default runner validates its
    // arguments as Sapling flags. These sinks report the others where the
    // operation queue hands them the client's arguments.
    ...["runExternalCommand", "runConfCommand", "runArcanistCommand"].map((runner): SinkSpec => ({
        kind: "callArgument",
        name: `isl_${runner}`,
        pattern: runner,
        argPositions: [1],
        description: `Tainted args passed to ${runner}(), which runs a program other than Sapling`,
        severity: "high",
        categories: ["arg_injection"],
    })),
    {
        kind: "callArgument",
        name: "isl_ejeca_stdin",
        pattern: "ejeca",
        argPositions: [2],
        objectProperties: ["input", "stdin"],
        requireObjectProperty: true,
        description: "Tainted standard input passed to ejeca()",
        severity: "medium",
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
    {
        kind: "callArgument",
        name: "fs_open_path",
        pattern: "fs.open",
        argPositions: [0],
        description: "Tainted path opened with fs.open",
        severity: "medium",
        categories: ["lfi"],
    },
    {
        // The extension lets its webview change editor settings. A tainted
        // name lets the sender pick which setting is written, including ones
        // that select an executable.
        kind: "callArgument",
        name: "vscode_config_update_key",
        pattern: "WorkspaceConfiguration.update",
        argPositions: [0],
        description: "Editor setting chosen by tainted data in WorkspaceConfiguration.update()",
        severity: "high",
        categories: ["file_write"],
    },
    {
        kind: "callArgument",
        name: "vscode_config_update_value",
        pattern: "WorkspaceConfiguration.update",
        argPositions: [1],
        reportingKind: "persistence_trace",
        description: "Tainted value persisted to editor settings; the setting's consumers are unverified",
        severity: "low",
        categories: ["file_integrity"],
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

/** The VS Code extension spec plus {@link IslSources} and {@link IslSinks}. */
export const islSpec: TaintSpec = {
    ...vscodeExtensionSpec,
    sources: [...vscodeExtensionSpec.sources, ...IslSources],
    sinks: [...vscodeExtensionSpec.sinks, ...IslSinks],
};
