/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SinkSpec } from "./types";

// Shared sink definitions used across multiple taint specs.
// Import individual sinks into spec files to avoid duplication.

// --- Command injection (RCE) ---

export const ExecSink: SinkSpec = {
    kind: "callArgument",
    name: "exec",
    pattern: "child_process.exec",
    argPositions: [0],
    description: "Command execution via child_process.exec",
    severity: "critical",
    categories: ["rce"],
};

export const ExecSyncSink: SinkSpec = {
    kind: "callArgument",
    name: "execSync",
    pattern: "child_process.execSync",
    argPositions: [0],
    description: "Synchronous command execution via child_process.execSync",
    severity: "critical",
    categories: ["rce"],
};

// spawn / execFile use a binary and argv without a shell by default. Model
// executable selection, argv, and execution-bearing options separately:
//
//   arg 0       binary             -> rce
//   arg 1       argv array         -> arg_injection
//   arg 1 or 2  options object     -> rce for shell or modeled env keys
//
// Executable operands to recognized shells/interpreters and shell-enabled
// calls upgrade argv findings to rce; see `isShellInvocation`. Ordinary data
// arguments to a fixed program remain argument-injection findings.

export const ChildProcessOptionProperties = [
    "argv0",
    "cwd",
    "detached",
    "encoding",
    "env",
    "gid",
    "input",
    "killSignal",
    "maxBuffer",
    "serialization",
    "shell",
    "signal",
    "stdio",
    "timeout",
    "uid",
    "windowsHide",
    "windowsVerbatimArguments",
];

// Environment keys modeled as execution-bearing. Known keys outside this
// list are excluded from these sinks; that is a modeling limit, not a claim
// that every child program treats them as harmless data.
export const ExecutionEnvironmentVariables = [
    // Executable lookup, and the shell that runs `shell: true` commands
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "SHELL",
    // Dynamic loader preloads and library search paths
    "LD_*",
    "DYLD_*",
    // Shell startup files and exported functions
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    "BASH_FUNC_*",
    // Interpreter options and module search paths
    "NODE_OPTIONS",
    "NODE_PATH",
    "ELECTRON_RUN_AS_NODE",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CLASSPATH",
    // Commands that tools run on the child's behalf
    "EDITOR",
    "VISUAL",
    "PAGER",
    "BROWSER",
    "LESSOPEN",
    "LESSCLOSE",
    "MANPAGER",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "GIT_*",
    "HGRCPATH",
    "NPM_CONFIG_*",
    // Where tools read configuration that can name commands to run
    "HOME",
    "XDG_CONFIG_HOME",
];

export const SpawnBinarySink: SinkSpec = {
    kind: "callArgument",
    name: "spawn",
    pattern: "child_process.spawn",
    argPositions: [0],
    description: "Executable path passed to child_process.spawn (attacker chooses the binary)",
    severity: "critical",
    categories: ["rce"],
};

export const SpawnArgsSink: SinkSpec = {
    kind: "callArgument",
    name: "spawn_args",
    pattern: "child_process.spawn",
    argPositions: [1],
    argumentShapes: { 1: "array" },
    rejectUnknownArgumentShapes: true,
    description: "Arguments passed to child_process.spawn (flag injection into a fixed binary)",
    severity: "high",
    categories: ["arg_injection"],
};

export const SpawnOptionsSink: SinkSpec = {
    kind: "callArgument",
    name: "spawn_options",
    pattern: "child_process.spawn",
    argPositions: [1, 2],
    argumentShapes: { 1: "object" },
    objectProperties: ["env", "shell"],
    objectPropertyUniverse: ChildProcessOptionProperties,
    objectPropertyKeys: { env: ExecutionEnvironmentVariables },
    description: "Execution-bearing options passed to child_process.spawn (env or shell)",
    severity: "critical",
    categories: ["rce"],
};

export const SpawnSyncBinarySink: SinkSpec = {
    ...SpawnBinarySink,
    name: "spawnSync",
    pattern: "child_process.spawnSync",
    description: "Executable path passed to child_process.spawnSync (attacker chooses the binary)",
};

export const SpawnSyncArgsSink: SinkSpec = {
    ...SpawnArgsSink,
    name: "spawnSync_args",
    pattern: "child_process.spawnSync",
    description: "Arguments passed to child_process.spawnSync (flag injection into a fixed binary)",
};

export const SpawnSyncOptionsSink: SinkSpec = {
    ...SpawnOptionsSink,
    name: "spawnSync_options",
    pattern: "child_process.spawnSync",
    description: "Execution-bearing options passed to child_process.spawnSync (env or shell)",
};

export const ExecFileBinarySink: SinkSpec = {
    ...SpawnBinarySink,
    name: "execFile",
    pattern: "child_process.execFile",
    description: "Executable path passed to child_process.execFile (attacker chooses the binary)",
};

export const ExecFileArgsSink: SinkSpec = {
    ...SpawnArgsSink,
    name: "execFile_args",
    pattern: "child_process.execFile",
    argumentShapes: { 1: "array" },
    rejectUnknownArgumentShapes: true,
    description: "Arguments passed to child_process.execFile (flag injection into a fixed binary)",
};

export const ExecFileOptionsSink: SinkSpec = {
    ...SpawnOptionsSink,
    name: "execFile_options",
    pattern: "child_process.execFile",
    argPositions: [1, 2],
    argumentShapes: { 1: "object" },
    description: "Execution-bearing options passed to child_process.execFile (env or shell)",
};

export const ExecFileSyncBinarySink: SinkSpec = {
    ...SpawnBinarySink,
    name: "execFileSync",
    pattern: "child_process.execFileSync",
    description: "Executable path passed to child_process.execFileSync (attacker chooses the binary)",
};

export const ExecFileSyncArgsSink: SinkSpec = {
    ...SpawnArgsSink,
    name: "execFileSync_args",
    pattern: "child_process.execFileSync",
    argumentShapes: { 1: "array" },
    rejectUnknownArgumentShapes: true,
    description: "Arguments passed to child_process.execFileSync (flag injection into a fixed binary)",
};

export const ExecFileSyncOptionsSink: SinkSpec = {
    ...SpawnOptionsSink,
    name: "execFileSync_options",
    pattern: "child_process.execFileSync",
    argPositions: [1, 2],
    argumentShapes: { 1: "object" },
    description: "Execution-bearing options passed to child_process.execFileSync (env or shell)",
};

// vscode-languageclient starts a language server from its `serverOptions`
// argument: `cp.spawn(command, args, options)` for an executable, or Node
// running `module` (with `runtime` as the binary, when set). The same split
// as spawn applies, by field rather than by position, so each field group is
// its own sink:
//
//   command, module, runtime  -> attacker chooses what runs           (rce)
//   args                      -> flag injection, or rce with shell    (arg_injection)
//   options.env, options.shell                                        (rce)
//
// `run`/`debug` (per-mode server options) and `options` are wrappers, so they
// are left out of the universe and skipped. Taint whose field is unknown,
// such as a whole options object from a setting, reports once, as rce.

const LanguageServerOptionProperties = [
    "command",
    "module",
    "runtime",
    "args",
    "transport",
    ...ChildProcessOptionProperties,
];

export const LanguageClientBinarySink: SinkSpec = {
    kind: "callArgument",
    name: "LanguageClient",
    pattern: "vscode-languageclient.LanguageClient",
    // new LanguageClient(id, name, serverOptions, ...) or (name, serverOptions, ...)
    argPositions: [1, 2],
    firstNonStringArgPosition: true,
    objectProperties: ["command", "module", "runtime"],
    objectPropertyUniverse: LanguageServerOptionProperties,
    description: "Language server executable or module started by vscode-languageclient (attacker chooses what runs)",
    severity: "critical",
    categories: ["rce"],
};

export const LanguageClientArgsSink: SinkSpec = {
    ...LanguageClientBinarySink,
    name: "LanguageClient_args",
    objectProperties: ["args"],
    requireObjectProperty: true,
    shellOptionsProperty: "options",
    description: "Arguments to a language server started by vscode-languageclient (flag injection into a fixed binary)",
    severity: "high",
    categories: ["arg_injection"],
};

export const LanguageClientOptionsSink: SinkSpec = {
    ...LanguageClientBinarySink,
    name: "LanguageClient_options",
    objectProperties: ["env", "shell"],
    objectPropertyKeys: { env: ExecutionEnvironmentVariables },
    requireObjectProperty: true,
    description: "Execution-bearing options of a language server started by vscode-languageclient (env or shell)",
    severity: "critical",
    categories: ["rce"],
};

// --- Code injection ---

export const EvalSink: SinkSpec = {
    kind: "callArgument",
    name: "eval",
    pattern: "eval",
    argPositions: [0],
    description: "Code execution via eval()",
    severity: "critical",
    categories: ["code_injection"],
};

export const FunctionConstructorSink: SinkSpec = {
    kind: "callArgument",
    name: "Function",
    pattern: "Function",
    allArguments: true,
    globalBuiltin: true,
    description: "Code execution via Function constructor",
    severity: "critical",
    categories: ["code_injection"],
};

// --- Network requests (SSRF) ---

export const FetchSink: SinkSpec = {
    kind: "callArgument",
    name: "fetch",
    pattern: "fetch",
    argPositions: [0],
    description: "HTTP fetch with attacker-controlled URL (SSRF/CSRF risk)",
    severity: "high",
    categories: ["ssrf"],
};

export const HttpRequestSink: SinkSpec = {
    kind: "callArgument",
    name: "http_request",
    pattern: "http.request",
    argPositions: [0],
    description: "HTTP request with attacker-controlled URL (SSRF/CSRF risk)",
    severity: "high",
    categories: ["ssrf"],
};

export const HttpsRequestSink: SinkSpec = {
    kind: "callArgument",
    name: "https_request",
    pattern: "https.request",
    argPositions: [0],
    description: "HTTPS request with attacker-controlled URL (SSRF/CSRF risk)",
    severity: "high",
    categories: ["ssrf"],
};

// --- File system ---

// Content control alone does not establish destination or consumer impact.
export const WriteFileContentSink: SinkSpec = {
    kind: "callArgument",
    name: "writeFile",
    pattern: "fs.writeFile",
    requireAPIIdentity: true,
    argPositions: [1],
    reportingKind: "persistence_trace",
    description: "Content persisted via Node.js; destination and consumer impact unverified",
    severity: "low",
    categories: ["file_integrity"],
};

export const WriteFileSink = WriteFileContentSink;

export const WriteFilePathSink: SinkSpec = {
    kind: "callArgument",
    name: "writeFile_path",
    pattern: "fs.writeFile",
    requireAPIIdentity: true,
    argPositions: [0],
    description: "File write to attacker-controlled path via Node.js fs module",
    severity: "high",
    categories: ["file_write"],
};

export const WriteFileSyncContentSink: SinkSpec = {
    ...WriteFileContentSink,
    name: "writeFileSync",
    pattern: "fs.writeFileSync",
    description: "Content persisted synchronously via Node.js; destination and consumer impact unverified",
};

export const WriteFileSyncSink = WriteFileSyncContentSink;

export const WriteFileSyncPathSink: SinkSpec = {
    kind: "callArgument",
    name: "writeFileSync_path",
    pattern: "fs.writeFileSync",
    requireAPIIdentity: true,
    argPositions: [0],
    description: "Synchronous file write to attacker-controlled path via Node.js fs module",
    severity: "high",
    categories: ["file_write"],
};
