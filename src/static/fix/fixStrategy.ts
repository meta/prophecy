/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SinkSpec, FixStrategy } from "../spec/types";

const DEFAULT_FIX_STRATEGIES: FixStrategy[] = [
    // exec/execSync → execFile (array form, no shell interpretation)
    {
        category: "rce",
        sinkName: "exec",
        saferAPI: "child_process.execFile",
        saferPattern: "execFile(program, [args], callback)",
        importPackage: "child_process",
        importName: "execFile",
        applicability: "unsafe",
        description:
            "Replace exec() with execFile() to avoid shell interpretation. " +
            "Split the command string into a program and argument array.",
    },
    {
        category: "rce",
        sinkName: "execSync",
        saferAPI: "child_process.execFileSync",
        saferPattern: "execFileSync(program, [args])",
        importPackage: "child_process",
        importName: "execFileSync",
        applicability: "unsafe",
        description:
            "Replace execSync() with execFileSync() to avoid shell interpretation. " +
            "Split the command string into a program and argument array.",
    },

    // terminal.sendText → quote args with shell-quote
    {
        category: "rce",
        sinkName: "sendText",
        saferAPI: "shell-quote",
        saferPattern: "terminal.sendText(quote([arg]))",
        importPackage: "shell-quote",
        importName: "quote",
        applicability: "unsafe",
        description:
            "Quote individual arguments for the target shell, not an entire command string. " +
            "Keep the command fixed and validate argument semantics; quoting alone is not a complete repair.",
    },

    // ShellExecution → ProcessExecution (array form)
    {
        category: "rce",
        sinkName: "ShellExecution",
        saferAPI: "vscode.ProcessExecution",
        saferPattern: "new ProcessExecution(program, [args])",
        importPackage: "vscode",
        importName: "ProcessExecution",
        applicability: "unsafe",
        description:
            "Replace ShellExecution with ProcessExecution to avoid shell interpretation. " +
            "Pass the program and arguments as separate values.",
    },

    // executeCommand with attacker-controlled command name → add allowlist
    {
        category: "rce",
        sinkName: "executeCommand",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Attacker-controlled command name passed to executeCommand cannot be mechanically fixed. " +
            "Add an allowlist of permitted command names.",
    },

    // startDebugging with attacker-controlled config → validate config shape
    {
        category: "rce",
        sinkName: "startDebugging",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Validate execution-bearing fields and restrict debugger types, programs, commands, " +
            "tasks, and adapter endpoints. Checking the object's shape alone is insufficient.",
    },

    // The program, argument, and options rules share these sink names.
    // None has a general mechanical repair.
    {
        category: "rce",
        sinkName: "spawn",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Use a trusted program with shell disabled, validate arguments for that program, " +
            "and restrict execution options such as cwd and env. Argument arrays do not prevent option injection.",
    },
    {
        category: "rce",
        sinkName: "spawnSync",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Use a trusted program with shell disabled, validate arguments for that program, " +
            "and restrict execution options such as cwd and env. Argument arrays do not prevent option injection.",
    },

    // eval / Function constructor — unfixable
    {
        category: "code_injection",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Dynamic code execution via eval()/Function() requires architectural change. " +
            "Remove dynamic code execution entirely.",
    },

    // XSS — escape-html
    {
        category: "xss",
        saferAPI: "escape-html",
        saferPattern: "escapeHtml(data)",
        importPackage: "escape-html",
        importName: "escapeHtml",
        applicability: "unsafe",
        description:
            "Use encoding appropriate to the output context. HTML escaping is not sufficient " +
            "for JavaScript, CSS, or URL contexts; review the suggested wrapper before applying it.",
    },

    // SSRF — unfixable (needs allowlist)
    {
        category: "ssrf",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Validate the scheme, host, and port against trusted destinations, and enforce the " +
            "same policy after redirects and DNS resolution. URL parsing alone does not prevent SSRF.",
    },

    // File-write paths — unfixable without a trusted base directory.
    {
        category: "file_write",
        sinkName: "writeFile_path",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Resolve the path against a trusted base directory and reject absolute or " +
            "parent-relative results. Account for symlinks when the target directory may be attacker-controlled.",
    },
    {
        category: "file_write",
        sinkName: "writeFileSync_path",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Resolve the path against a trusted base directory and reject absolute or " +
            "parent-relative results. Account for symlinks when the target directory may be attacker-controlled.",
    },
    {
        category: "file_write",
        sinkName: "vscode_writeFile_path",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Resolve the path against a trusted base directory and reject absolute or " +
            "parent-relative results. Account for symlinks when the target directory may be attacker-controlled.",
    },

    // File-write content — review integrity impact and destination semantics.
    {
        category: "file_integrity",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Validate content against the destination's schema and allowlist security-sensitive fields. " +
            "Review whether a later privileged consumer interprets the stored content.",
    },

    // open_redirect — validate URL protocol
    {
        category: "open_redirect",
        sinkName: "openExternal",
        saferAPI: "vscode.Uri.parse",
        saferPattern: 'if (uri.scheme === "https") { openExternal(uri); }',
        applicability: "unfixable",
        description:
            "Validate the URL scheme and destination against the application's allowed targets. " +
            "Restricting the scheme to https alone does not prevent attacker-controlled redirects.",
    },

    // workspace_edit — unfixable
    {
        category: "workspace_edit",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Workspace edit with attacker-controlled content requires manual review. " +
            "Validate edit content and restrict target file paths.",
    },

    // prompt_injection — unfixable
    {
        category: "prompt_injection",
        saferAPI: "",
        saferPattern: "",
        applicability: "unfixable",
        description:
            "Attacker-controlled text in an agent prompt requires manual review. " +
            "Do not send untrusted input as instructions to an agent that can edit files or run commands.",
    },
];

export function resolveFixStrategy(sink: SinkSpec, specOverrides?: FixStrategy[]): FixStrategy | undefined {
    // Check spec overrides first (match on sinkName if present, then category)
    if (specOverrides) {
        const byName = specOverrides.find((s) => s.sinkName && s.sinkName === sink.name);
        if (byName) return byName;

        const byCat = specOverrides.find((s) => !s.sinkName && sink.categories.includes(s.category));
        if (byCat) return byCat;
    }

    // Then check defaults — prefer sink-name-specific, fall back to category-only
    const byName = DEFAULT_FIX_STRATEGIES.find((s) => s.sinkName && s.sinkName === sink.name);
    if (byName) return byName;

    const byCat = DEFAULT_FIX_STRATEGIES.find((s) => !s.sinkName && sink.categories.includes(s.category));
    return byCat;
}
