/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { Internal } from "../Internal";
import { TaintSpec } from "./types";
import { LanguageClientBinarySink, LanguageClientArgsSink, LanguageClientOptionsSink } from "./sinks";
import { NodeSinks, NodeFileSources } from "./nodeApis";
import { NumberSanitizer, ParseIntSanitizer } from "./sanitizers";

const WORKSPACE_COMMAND_OUTPUT =
    "Output of a command run in a workspace folder (attacker-controlled in an untrusted checkout)";

/**
 * Built-in taint specification for VS Code extension security analysis.
 * Focuses on command injection, code injection, and file manipulation.
 */
export const vscodeExtensionSpec: TaintSpec = {
    entryFunctions: ["activate"],
    // Analyze host-invoked provider methods without a direct extension call.
    // Actual invocation depends on editor features and user interaction;
    // registering a provider does not guarantee it runs when a file opens.
    handlerEntryPoints: [
        {
            registration: "registerCodeLensProvider",
            argIndex: 1,
            method: "provideCodeLenses",
            description: "Code lens provider (provideCodeLenses)",
        },
        {
            registration: "registerCodeActionsProvider",
            argIndex: 1,
            method: "provideCodeActions",
            description: "Code action provider (provideCodeActions)",
        },
        {
            registration: "registerHoverProvider",
            argIndex: 1,
            method: "provideHover",
            description: "Hover provider (provideHover)",
        },
        {
            registration: "registerDocumentLinkProvider",
            argIndex: 1,
            method: "provideDocumentLinks",
            description: "Document link provider (provideDocumentLinks)",
        },
        {
            registration: "registerInlayHintsProvider",
            argIndex: 1,
            method: "provideInlayHints",
            description: "Inlay hints provider (provideInlayHints)",
        },
        {
            registration: "registerDocumentSymbolProvider",
            argIndex: 1,
            method: "provideDocumentSymbols",
            description: "Document symbol provider (provideDocumentSymbols)",
        },
        {
            registration: "registerFoldingRangeProvider",
            argIndex: 1,
            method: "provideFoldingRanges",
            description: "Folding range provider (provideFoldingRanges)",
        },
        {
            registration: "registerDocumentSemanticTokensProvider",
            argIndex: 1,
            method: "provideDocumentSemanticTokens",
            description: "Semantic tokens provider (provideDocumentSemanticTokens)",
        },
        {
            registration: "registerColorProvider",
            argIndex: 1,
            method: "provideDocumentColors",
            description: "Document color provider (provideDocumentColors)",
        },
    ],
    sources: [
        // URI handler — deeplink parameters (T226511721 pattern)
        {
            kind: "parameter",
            pattern: "handleUri.uri",
            description: "URI handler parameter (attacker-controlled via vscode:// deeplink)",
            taintAllProperties: true,
            callbackRegistration: "registerUriHandler",
            handlerMethod: "handleUri",
            entryPointDescription: "URI handler (vscode:// deeplink)",
        },

        // Treat debug configuration callbacks as source boundaries for configs
        // from launch.json or startDebugging. The host-mediated round trip
        // between registration, configuration resolution, and session creation
        // is not modeled as a continuous taint path.
        {
            kind: "parameter",
            pattern: "resolveDebugConfiguration.config",
            description:
                "Debug configuration (attacker-controlled via .vscode/launch.json, or a deeplink reaching startDebugging)",
            taintAllProperties: true,
            callbackRegistration: "registerDebugConfigurationProvider",
            callbackArgIndex: 1,
            handlerMethod: "resolveDebugConfiguration",
            paramIndex: 1,
            entryPointDescription: "Debug configuration provider (resolveDebugConfiguration)",
        },
        {
            kind: "parameter",
            pattern: "process.codeGenCommand",
            description: "Declared code generator command (attacker-controlled by repository source)",
            taintAllProperties: true,
            callbackRegistration: "registerDebugConfigurationProvider",
            callbackArgIndex: 1,
            handlerMethod: "resolveDebugConfiguration",
            paramIndex: 0,
            entryPointDescription: "Code generator configuration provider (resolveDebugConfiguration)",
        },
        {
            kind: "parameter",
            pattern: "resolveDebugConfigurationWithSubstitutedVariables.config",
            description:
                "Debug configuration (attacker-controlled via .vscode/launch.json, or a deeplink reaching startDebugging)",
            taintAllProperties: true,
            callbackRegistration: "registerDebugConfigurationProvider",
            callbackArgIndex: 1,
            handlerMethod: "resolveDebugConfigurationWithSubstitutedVariables",
            paramIndex: 1,
            entryPointDescription: "Debug configuration provider (resolveDebugConfigurationWithSubstitutedVariables)",
        },
        {
            kind: "parameter",
            pattern: "createDebugAdapterDescriptor.session",
            description:
                "Debug session configuration (attacker-controlled via .vscode/launch.json, or a deeplink reaching startDebugging)",
            taintAllProperties: true,
            callbackRegistration: "registerDebugAdapterDescriptorFactory",
            callbackArgIndex: 1,
            handlerMethod: "createDebugAdapterDescriptor",
            paramIndex: 0,
            entryPointDescription: "Debug adapter descriptor factory (createDebugAdapterDescriptor)",
        },

        // User input dialogs
        {
            kind: "callReturnValue",
            pattern: "vscode.window.showInputBox",
            description: "User input from input box dialog",
        },
        {
            kind: "callReturnValue",
            pattern: "vscode.window.showQuickPick",
            description: "User selection from quick pick dialog",
            selectionFromArgIndex: 0,
            taintAllProperties: true,
        },

        // Clipboard
        {
            kind: "callReturnValue",
            pattern: "vscode.env.clipboard.readText",
            description: "Clipboard content (potentially attacker-controlled)",
        },

        // Webview messages
        {
            kind: "parameter",
            pattern: "onDidReceiveMessage.message",
            description: "Message from webview (potentially attacker-controlled content)",
            taintAllProperties: true,
            callbackRegistration: "onDidReceiveMessage",
        },

        // Extension settings (can be workspace-level, so attacker can set via .vscode/settings.json)
        {
            kind: "callReturnValue",
            pattern: "WorkspaceConfiguration.get",
            description: "Workspace configuration value (attacker-controlled via .vscode/settings.json)",
            taintAllProperties: true,
            // Scope changes the source label, not whether the value is tainted.
            // These scopes do not read from workspace settings.
            settingScopeDescriptions: {
                machine: "Machine-scoped setting (user or remote Machine settings; not .vscode/settings.json)",
                application: "Application-scoped setting (user settings; not .vscode/settings.json)",
            },
        },

        // File reads introduce content taint even when the path is untainted.
        // The callback form inherits path taint when available, otherwise
        // creates a file-content source.
        {
            kind: "callReturnValue",
            pattern: "vscode.workspace.fs.readFile",
            requireAPIIdentity: true,
            description: "File content read via VS Code API",
        },
        ...NodeFileSources,

        {
            kind: "callReturnValue",
            pattern: "TextDocument.getText",
            resolvedPattern: "vscode.TextDocument.getText",
            description: "Open document content (attacker-controlled in an untrusted checkout)",
        },

        // Directory listings and searches expose attacker-chosen filenames,
        // independently of file contents. Interpolating those names into shell
        // commands can turn filename syntax into code.
        {
            kind: "callReturnValue",
            pattern: "vscode.workspace.fs.readDirectory",
            description: "Directory listing (filenames are attacker-controlled in an untrusted checkout)",
            taintAllProperties: true,
        },
        {
            kind: "callReturnValue",
            pattern: "vscode.workspace.findFiles",
            description: "Workspace file search results (filenames are attacker-controlled in an untrusted checkout)",
            taintAllProperties: true,
        },
        {
            kind: "callReturnValue",
            pattern: "fs.readdir",
            description: "Directory listing (filenames are attacker-controlled in an untrusted checkout)",
            taintAllProperties: true,
        },
        {
            kind: "callReturnValue",
            pattern: "fs.readdirSync",
            description: "Directory listing (filenames are attacker-controlled in an untrusted checkout)",
            taintAllProperties: true,
        },
        {
            kind: "parameter",
            pattern: "readdir.files",
            description: "Directory listing (filenames are attacker-controlled in an untrusted checkout)",
            taintAllProperties: true,
            callbackRegistration: "readdir",
            callbackArgIndices: [1, 2],
            callbackSource: "call",
            callbackTaint: "preferArgTaint",
            callbackTaintFromArgIndex: 0,
            paramIndex: 1,
        },
        {
            kind: "callReturnValue",
            pattern: "glob.sync",
            description: "Glob match results (filenames are attacker-controlled in an untrusted checkout)",
            taintAllProperties: true,
        },
        {
            kind: "propertyAccess",
            pattern: "vscode.TextDocument.fileName",
            description: "Open document path (attacker-controlled in an untrusted checkout)",
        },

        // Model command output as a source when a recognized cwd points into
        // the workspace. Output may contain repository-controlled filenames,
        // branch names, or configuration; the command's behavior is not checked.
        {
            kind: "callReturnValue",
            pattern: "child_process.exec",
            description: WORKSPACE_COMMAND_OUTPUT,
            taintAllProperties: true,
            promisified: true,
            workspaceCwdOptionIndices: [1],
            workspaceDefaultCwd: true,
        },
        {
            kind: "callReturnValue",
            pattern: "child_process.execFile",
            description: WORKSPACE_COMMAND_OUTPUT,
            taintAllProperties: true,
            promisified: true,
            workspaceCwdOptionIndices: [1, 2],
        },
        {
            kind: "callReturnValue",
            pattern: "child_process.execSync",
            description: WORKSPACE_COMMAND_OUTPUT,
            workspaceCwdOptionIndices: [1],
        },
        {
            kind: "callReturnValue",
            pattern: "child_process.execFileSync",
            description: WORKSPACE_COMMAND_OUTPUT,
            workspaceCwdOptionIndices: [1, 2],
        },
        {
            kind: "parameter",
            pattern: "exec.stdout",
            description: WORKSPACE_COMMAND_OUTPUT,
            callbackRegistration: "child_process.exec",
            callbackArgIndices: [2],
            callbackSource: "call",
            paramIndex: 1,
            workspaceCwdOptionIndices: [1],
        },
        {
            kind: "parameter",
            pattern: "execFile.stdout",
            description: WORKSPACE_COMMAND_OUTPUT,
            callbackRegistration: "child_process.execFile",
            callbackArgIndices: [2, 3],
            callbackSource: "call",
            paramIndex: 1,
            workspaceCwdOptionIndices: [1, 2],
        },

        {
            kind: "parameter",
            pattern: "provideTextDocumentContent.uri",
            description: "Document-provider URI (may contain attacker-controlled query or path data)",
            taintAllProperties: true,
            callbackRegistration: "registerTextDocumentContentProvider",
            callbackArgIndex: 1,
            handlerMethod: "provideTextDocumentContent",
            paramIndex: 0,
            entryPointDescription: "Text document content provider",
        },

        // HTTP server request (attacker-controlled when server binds to external interface)
        {
            kind: "parameter",
            pattern: "createServer.req",
            description: "HTTP request object (attacker-controlled when server is externally reachable)",
            taintAllProperties: true,
            callbackRegistration: "createServer",
            paramIndex: 0,
        },

        // `process.env` is deliberately outside this spec's source boundary.
        // Taint from modeled sources, such as settings or file reads, can still
        // reach child-process environment sinks.

        // WebSocket/EventEmitter message data (attacker-controlled when server accepts external connections)
        {
            kind: "parameter",
            pattern: "onMessage.data",
            description:
                "WebSocket/EventEmitter message data (attacker-controlled when server accepts external connections)",
            taintAllProperties: true,
            callbackRegistration: "onMessage",
            paramIndex: 0,
        },
    ],

    sinks: [
        // Shared Node.js APIs plus language-server launch options.
        ...NodeSinks,
        LanguageClientBinarySink,
        LanguageClientArgsSink,
        LanguageClientOptionsSink,

        // VS Code-specific sinks
        {
            kind: "callArgument",
            name: "sendText",
            pattern: "Terminal.sendText",
            argPositions: [0],
            description: "Text sent to VS Code terminal",
            severity: "critical",
            categories: ["rce"],
        },
        {
            kind: "callArgument",
            name: "ShellExecution",
            pattern: "vscode.ShellExecution",
            argPositions: [0],
            description: "Shell command via VS Code ShellExecution",
            severity: "critical",
            categories: ["rce"],
        },
        {
            kind: "callArgument",
            name: "executeCommand",
            pattern: "vscode.commands.executeCommand",
            argPositions: [0],
            description:
                "VS Code command execution (attacker-controlled command name enables RCE via terminal.sendSequence, etc.)",
            severity: "critical",
            categories: ["rce"],
        },
        {
            kind: "callArgument",
            name: "startDebugging",
            pattern: "debug.startDebugging",
            argPositions: [1],
            // Select execution-bearing fields rather than cosmetic fields such
            // as `name`. Debugger-command fields can run code; adapter-redirection
            // fields can direct the session to an attacker-controlled adapter.
            // Unknown property provenance still reports (see `objectProperties`).
            objectProperties: [
                // `request` selects launch vs attach, which changes WHICH fields
                // the adapter honors — flipping attach to launch can make an
                // otherwise inert `program` execute.
                "request",
                // debugger commands — lldb-dap, cppdbg
                "initCommands",
                "attachCommands",
                "preRunCommands",
                "postRunCommands",
                "exitCommands",
                "setupCommands",
                "customLaunchSetupCommands",
                // what gets executed
                "program",
                "runtimeExecutable",
                "runtimeArgs",
                "args",
                "miDebuggerPath",
                "debugServer",
                // tasks run around the session
                "preLaunchTask",
                "postDebugTask",
                // execution environment
                "env",
                "envFile",
                "cwd",
                // adapter redirection
                "connect",
                "host",
                "port",
            ],
            description: "Execution-bearing debug configuration field passed to startDebugging",
            severity: "critical",
            categories: ["rce"],
        },
        {
            kind: "callArgument",
            name: "vscode_writeFile",
            pattern: "vscode.workspace.fs.writeFile",
            requireAPIIdentity: true,
            argPositions: [1],
            reportingKind: "persistence_trace",
            description: "Content persisted via VS Code; destination and consumer impact unverified",
            severity: "low",
            categories: ["file_integrity"],
        },
        {
            kind: "callArgument",
            name: "vscode_writeFile_path",
            pattern: "vscode.workspace.fs.writeFile",
            requireAPIIdentity: true,
            argPositions: [0],
            description: "File write to attacker-controlled path via VS Code API",
            severity: "high",
            categories: ["file_write"],
        },
        {
            kind: "callArgument",
            name: "openExternal",
            pattern: "vscode.env.openExternal",
            argPositions: [0],
            description: "Opens URL in external browser (phishing, OAuth token theft via attacker-controlled redirect)",
            severity: "high",
            categories: ["open_redirect"],
        },

        // Webview HTML
        {
            kind: "assignment",
            name: "webview_html",
            pattern: "vscode.Webview.html",
            description: "Attacker-controlled HTML assigned to a VS Code webview",
            severity: "high",
            categories: ["xss"],
        },

        // Workspace edits — attacker-controlled content written to files
        {
            kind: "callArgument",
            name: "applyEdit",
            pattern: "workspace.applyEdit",
            argPositions: [0],
            description: "Workspace edit with attacker-controlled content (arbitrary file modification)",
            severity: "high",
            categories: ["workspace_edit"],
        },

        // Commands of internal extensions; none in open source builds.
        ...(Internal.vscodeExtensionSinks ?? []),
    ],

    sanitizers: [
        {
            kind: "callReturnValue",
            pattern: "shlex.quote",
            description: "Shell argument quoting sanitizes command injection",
            categories: ["rce"],
            sinkNames: ["exec", "execSync", "sendText", "ShellExecution"],
            requiresShellArgumentContext: true,
            shellCommandDenylist: [
                // Shells and interpreters run a quoted argument as code (`-c`, `-e`, script path).
                "sh",
                "bash",
                "zsh",
                "dash",
                "ksh",
                "fish",
                "csh",
                "tcsh",
                "python",
                "python2",
                "python3",
                "node",
                "deno",
                "bun",
                "perl",
                "ruby",
                "php",
                "lua",
                "tclsh",
                "osascript",
                "pwsh",
                "powershell",
                "cmd",
                "awk",
                "gawk",
                "sed",
                "expect",
                "pypy",
                "ipython",
                "irb",
                "rscript",
                "julia",
                "java",
                "jshell",
                // Package runners execute the package or script named by their argument.
                "npx",
                "bunx",
                "uvx",
                "pipx",
                "npm",
                "yarn",
                "pnpm",
                // Keywords and builtins: the first token is not the command that runs.
                "if",
                "then",
                "else",
                "elif",
                "fi",
                "do",
                "done",
                "while",
                "until",
                "for",
                "case",
                "esac",
                "select",
                "function",
                "coproc",
                "!",
                "{",
                "(",
                "[[",
                "source",
                ".",
                "command",
                "builtin",
                "trap",
                "alias",
                // Wrappers run their arguments as a command.
                "eval",
                "exec",
                "env",
                "sudo",
                "doas",
                "su",
                "nohup",
                "timeout",
                "nice",
                "time",
                "watch",
                "stdbuf",
                "xargs",
                "parallel",
                "script",
                // Remote and container execution.
                "ssh",
                "docker",
                "podman",
                "kubectl",
                "adb",
                // A quoted value can still be an option that runs code
                // (`--upload-pack=`, `-oProxyCommand=`, `-exec`, `-e`, `--checkpoint-action=`).
                "git",
                "scp",
                "rsync",
                "find",
                "tar",
                "zip",
            ],
        },
        ParseIntSanitizer,
        NumberSanitizer,
    ],
};
