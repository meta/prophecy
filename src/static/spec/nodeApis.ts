/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SinkSpec, SourceSpec } from "./types";
import {
    ChildProcessOptionProperties,
    ExecutionEnvironmentVariables,
    ExecSink,
    ExecSyncSink,
    SpawnBinarySink,
    SpawnArgsSink,
    SpawnOptionsSink,
    SpawnSyncBinarySink,
    SpawnSyncArgsSink,
    SpawnSyncOptionsSink,
    ExecFileBinarySink,
    ExecFileArgsSink,
    ExecFileOptionsSink,
    ExecFileSyncBinarySink,
    ExecFileSyncArgsSink,
    ExecFileSyncOptionsSink,
    EvalSink,
    FunctionConstructorSink,
    FetchSink,
    HttpGetSink,
    HttpRequestSink,
    HttpsGetSink,
    HttpsRequestSink,
    WriteFileSink,
    WriteFilePathSink,
    WriteFileSyncSink,
    WriteFileSyncPathSink,
} from "./sinks";

const ExecaOptionProperties = [
    ...ChildProcessOptionProperties,
    "all",
    "buffer",
    "cleanup",
    "extendEnv",
    "execPath",
    "localDir",
    "preferLocal",
    "reject",
    "stderr",
    "stdin",
    "stdout",
    "stripFinalNewline",
];

// Execa 5's callable default and .sync and Execa 6+'s named exports share
// (file, argv?, options?) / (file, options?). Execa 9 also accepts a single
// options object to bind a method; that call does not execute a program.
// Tagged templates, bound methods, .command and .node have different contracts
// and are deliberately not approximated as positional child_process calls.
function processWrapperSinks(pattern: string, name: string, execa = false): SinkSpec[] {
    return [
        {
            ...SpawnBinarySink,
            name,
            pattern,
            requireAPIIdentity: true,
            ...(execa ? { argumentShapes: { 0: "string" as const } } : {}),
            description: `Executable selected via ${pattern}`,
        },
        {
            ...SpawnArgsSink,
            name: `${name}_args`,
            pattern,
            requireAPIIdentity: true,
            description: `Arguments passed via ${pattern} (flag injection into a fixed executable)`,
        },
        {
            ...SpawnOptionsSink,
            name: `${name}_options`,
            pattern,
            requireAPIIdentity: true,
            objectPropertyUniverse: execa ? ExecaOptionProperties : ChildProcessOptionProperties,
            objectProperties: ["env", "shell"],
            objectPropertyKeys: { env: ExecutionEnvironmentVariables },
            description: `Execution-bearing options passed via ${pattern}`,
        },
    ];
}

export const ExecaSinks: SinkSpec[] = [
    ...processWrapperSinks("execa", "execa", true),
    ...processWrapperSinks("execa.sync", "execa_sync", true),
    ...processWrapperSinks("execa.execa", "execa_named", true),
    ...processWrapperSinks("execa.execaSync", "execa_named_sync", true),
];

export const CrossSpawnSinks: SinkSpec[] = [
    ...processWrapperSinks("cross-spawn", "cross_spawn"),
    ...processWrapperSinks("cross-spawn.spawn", "cross_spawn_spawn"),
    ...processWrapperSinks("cross-spawn.sync", "cross_spawn_sync"),
];

// Axios 1.13.1: AxiosInstance(config) and AxiosInstance(url, config),
// request(config) (also request(url, config) at runtime), get/delete/head/options
// (url, config), and post/put/patch[Form](url, data, config). Payload data,
// query params and headers are not request destinations. No host allowlist or
// URL encoding is assumed to sanitize a destination. baseURL stays conservative:
// a fixed absolute URL can make it inert under normal defaults, but instance or
// request allowAbsoluteUrls policy is not inferred by these field-only models.
const AxiosConfigProperties = [
    "url",
    "method",
    "baseURL",
    "allowAbsoluteUrls",
    "transformRequest",
    "transformResponse",
    "headers",
    "params",
    "paramsSerializer",
    "data",
    "timeout",
    "timeoutErrorMessage",
    "withCredentials",
    "adapter",
    "auth",
    "responseType",
    "responseEncoding",
    "xsrfCookieName",
    "xsrfHeaderName",
    "onUploadProgress",
    "onDownloadProgress",
    "maxContentLength",
    "validateStatus",
    "maxBodyLength",
    "maxRedirects",
    "maxRate",
    "beforeRedirect",
    "socketPath",
    "transport",
    "httpAgent",
    "httpsAgent",
    "proxy",
    "cancelToken",
    "decompress",
    "transitional",
    "signal",
    "insecureHTTPParser",
    "env",
    "formSerializer",
    "family",
    "lookup",
    "withXSRFToken",
    "parseReviver",
    "fetchOptions",
];

function axiosSinks(pattern: string, name: string, configPosition: number, overloaded = false): SinkSpec[] {
    const url: SinkSpec = {
        kind: "callArgument",
        name,
        pattern,
        requireAPIIdentity: true,
        argPositions: [0],
        ...(overloaded ? { argumentShapes: { 0: "string" as const } } : {}),
        description: `Request URL passed to ${pattern}`,
        severity: "high",
        categories: ["ssrf"],
    };
    const config: SinkSpec = {
        ...url,
        name: `${name}_config`,
        argPositions: [configPosition],
        argumentShapes: { [configPosition]: "object" },
        objectProperties: ["url", "baseURL", "socketPath", "proxy"],
        objectPropertyUniverse: AxiosConfigProperties,
        objectPropertyKeys: { proxy: ["host", "port", "protocol"] },
        description: `Request destination in ${pattern} configuration (not payload data)`,
    };
    return overloaded
        ? [
              url,
              { ...config, name, argPositions: [0], argumentShapes: { 0: "object" } },
              // The explicit URL overwrites config.url in the URL overload.
              { ...config, objectProperties: ["baseURL", "socketPath", "proxy"] },
          ]
        : [
              url,
              // Method aliases overwrite config.url with the first argument too.
              { ...config, objectProperties: ["baseURL", "socketPath", "proxy"] },
          ];
}

export const AxiosSinks: SinkSpec[] = [
    ...axiosSinks("axios", "axios", 1, true),
    ...axiosSinks("axios.request", "axios_request", 1, true),
    ...["get", "delete", "head", "options"].flatMap((method) => axiosSinks(`axios.${method}`, `axios_${method}`, 1)),
    ...["post", "put", "patch", "postForm", "putForm", "patchForm"].flatMap((method) =>
        axiosSinks(`axios.${method}`, `axios_${method}`, 2),
    ),
];

export const NodeFileReadSinks: SinkSpec[] = ["readFile", "readFileSync", "createReadStream"].map((method) => ({
    kind: "callArgument",
    name: `${method}_path`,
    pattern: `fs.${method}`,
    requireAPIIdentity: true,
    argPositions: [0],
    ...(method === "createReadStream" ? { pathOverriddenByFileDescriptor: { argument: 1, property: "fd" } } : {}),
    description: `Input-dependent file read path via fs.${method} (no disclosure or privilege crossing established)`,
    severity: "low",
    categories: ["file_access"],
}));

export const NodeFileAppendSinks: SinkSpec[] = ["appendFile", "appendFileSync"].flatMap((method) => [
    {
        ...WriteFilePathSink,
        name: `${method}_path`,
        pattern: `fs.${method}`,
        requireAPIIdentity: true,
        description: `File append to an attacker-controlled path via fs.${method}`,
    },
    {
        ...WriteFileSink,
        name: method,
        pattern: `fs.${method}`,
        requireAPIIdentity: true,
        description: `Attacker-controlled content appended via fs.${method}`,
    },
]);

export const CreateWriteStreamSink: SinkSpec = {
    ...WriteFilePathSink,
    name: "createWriteStream_path",
    pattern: "fs.createWriteStream",
    requireAPIIdentity: true,
    pathOverriddenByFileDescriptor: { argument: 1, property: "fd" },
    description: "File output stream opened at an attacker-controlled path",
};

// Content sources are opt-in: a file-access sink does not imply that every file
// in every host environment is attacker-controlled. Callback reads supply data
// at parameter 1; the callback-form return value is void, not file content.
export const NodeFileSources: SourceSpec[] = [
    {
        kind: "parameter",
        pattern: "fs.readFile.data",
        requireAPIIdentity: true,
        description: "File content read via Node.js fs module",
        taintAllProperties: true,
        callbackRegistration: "fs.readFile",
        callbackArgIndices: [1, 2],
        callbackSource: "call",
        callbackTaint: "preferArgTaint",
        callbackTaintFromArgIndex: 0,
        paramIndex: 1,
    },
    {
        kind: "callReturnValue",
        pattern: "fs.readFileSync",
        requireAPIIdentity: true,
        description: "File content read synchronously via Node.js fs module",
        taintAllProperties: true,
    },
    {
        kind: "callReturnValue",
        pattern: "fs.readFile",
        requireAPIIdentity: true,
        callReturnKind: "promise",
        description: "File content read via Node.js promise file APIs",
        taintAllProperties: true,
    },
    // The tracker stores this source on stream data, not on the handle or its
    // path/fd metadata. Only data consumers receive the content taint.
    {
        kind: "callReturnValue",
        pattern: "fs.createReadStream",
        requireAPIIdentity: true,
        description: "File content delivered by a Node.js read stream",
        taintAllProperties: true,
    },
];

export const NodeCommandSinks: SinkSpec[] = [
    ExecSink,
    ExecSyncSink,
    SpawnBinarySink,
    SpawnArgsSink,
    SpawnOptionsSink,
    SpawnSyncBinarySink,
    SpawnSyncArgsSink,
    SpawnSyncOptionsSink,
    ExecFileBinarySink,
    ExecFileArgsSink,
    ExecFileOptionsSink,
    ExecFileSyncBinarySink,
    ExecFileSyncArgsSink,
    ExecFileSyncOptionsSink,
    ...ExecaSinks,
    ...CrossSpawnSinks,
];

export const NodeNetworkSinks: SinkSpec[] = [
    FetchSink,
    HttpRequestSink,
    HttpsRequestSink,
    HttpGetSink,
    HttpsGetSink,
    ...AxiosSinks,
];
export const NodeCodeSinks: SinkSpec[] = [EvalSink, FunctionConstructorSink];
export const NodeFileSinks: SinkSpec[] = [
    WriteFilePathSink,
    WriteFileSink,
    WriteFileSyncPathSink,
    WriteFileSyncSink,
    ...NodeFileReadSinks,
    ...NodeFileAppendSinks,
    CreateWriteStreamSink,
];
export const NodeSinks: SinkSpec[] = [...NodeCommandSinks, ...NodeCodeSinks, ...NodeNetworkSinks, ...NodeFileSinks];
