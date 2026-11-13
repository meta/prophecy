/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";

interface CachedDeclaration {
    sourceFile: ts.SourceFile;
    parseOptions: string;
}

/** Internal to inline analysis: callers must not expose or mutate the cached ASTs. */
export class InlineDeclarationCache {
    private readonly declarations = new Map<string, CachedDeclaration>();
    private environment: string | undefined;
    private textBytes = 0;

    constructor(
        private readonly maxFiles = 256,
        private readonly maxTextBytes = 16 * 1024 * 1024,
    ) {}

    createCompilerHost(options: ts.CompilerOptions): ts.CompilerHost {
        const host = ts.createCompilerHost(options);
        // Binding depends on compiler options; relative paths depend on the cwd.
        // Keep only one environment, rather than accumulating option generations.
        const resetEnvironment = (): void => {
            const environment = JSON.stringify([
                ts.version,
                host.getCurrentDirectory(),
                host.useCaseSensitiveFileNames(),
                options,
            ]);
            if (environment !== this.environment) {
                this.declarations.clear();
                this.textBytes = 0;
                this.environment = environment;
            }
        };
        const getSourceFile = host.getSourceFile;
        host.getSourceFile = (name, languageVersion, onError, shouldCreateNewSourceFile) => {
            resetEnvironment();
            if (!/\.d\.(?:ts|mts|cts)$/i.test(name)) {
                return getSourceFile(name, languageVersion, onError, shouldCreateNewSourceFile);
            }
            // The default host's module-indicator callback is derived from the exact
            // compiler options above. The remaining per-file parse inputs vary with
            // package metadata, even when the compiler options have not changed.
            const parseOptions = JSON.stringify(
                typeof languageVersion === "number"
                    ? languageVersion
                    : [
                          languageVersion.languageVersion,
                          languageVersion.impliedNodeFormat,
                          languageVersion.jsDocParsingMode,
                      ],
            );
            const cached = this.declarations.get(name);
            if (cached && !shouldCreateNewSourceFile && cached.parseOptions === parseOptions) {
                // Re-read content, not mtimes: replacements can preserve size/time.
                const text = host.readFile(name);
                if (text !== undefined && text === cached.sourceFile.text) {
                    this.declarations.delete(name);
                    this.declarations.set(name, cached);
                    return cached.sourceFile;
                }
            }
            if (cached) this.remove(name, cached);
            const sourceFile = getSourceFile(name, languageVersion, onError, shouldCreateNewSourceFile);
            if (
                sourceFile?.isDeclarationFile &&
                sourceFile.text.length * 2 <= this.maxTextBytes &&
                this.maxFiles > 0 &&
                this.isReusableDeclaration(sourceFile)
            ) {
                const bytes = sourceFile.text.length * 2;
                while (this.declarations.size >= this.maxFiles || this.textBytes + bytes > this.maxTextBytes) {
                    const [oldName, old] = this.declarations.entries().next().value!;
                    this.remove(oldName, old);
                }
                this.declarations.set(name, { sourceFile, parseOptions });
                this.textBytes += bytes;
            }
            return sourceFile;
        };
        return host;
    }

    private isReusableDeclaration(sourceFile: ts.SourceFile): boolean {
        // Malformed .d.ts files can contain executable bodies and defaults.
        // Analyzer free-symbol/captured-write caches are keyed by function AST,
        // so only body-less, default-free declarations can be shared safely.
        const pending: ts.Node[] = [sourceFile];
        while (pending.length > 0) {
            const node = pending.pop()!;
            if (
                (ts.isFunctionLike(node) && (node as ts.FunctionLikeDeclaration).body) ||
                (ts.isParameter(node) && node.initializer) ||
                ts.isClassStaticBlockDeclaration(node)
            ) {
                return false;
            }
            node.forEachChild((child) => {
                pending.push(child);
            });
        }
        return true;
    }

    private remove(name: string, cached: CachedDeclaration): void {
        this.declarations.delete(name);
        this.textBytes -= cached.sourceFile.text.length * 2;
    }
}
