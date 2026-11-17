/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as ts from "typescript";
import * as path from "path";
import { InlineDeclarationCache } from "./inlineDeclarationCache";

const inlineDeclarations = new InlineDeclarationCache();

export interface ParsedProject {
    program: ts.Program;
    checker: ts.TypeChecker;
    sourceFiles: ts.SourceFile[];
}

/**
 * Parse a TypeScript project from its root directory.
 * Looks for tsconfig.json in this directory and then its ancestors.
 *
 * Excluded paths are removed from the root-file list before program creation
 * and from the returned sourceFiles. Imports can still bring them into the
 * TypeScript program. Each nonempty exclusion is a literal path substring.
 */
export function parseProject(projectDir: string, excludePaths: string[] = []): ParsedProject {
    const configPath = ts.findConfigFile(projectDir, ts.sys.fileExists, "tsconfig.json");

    const isExcluded = (fileName: string): boolean => excludePaths.some((p) => p.length > 0 && fileName.includes(p));

    let program: ts.Program;

    if (configPath) {
        const configFile = ts.readConfigFile(configPath, ts.sys.readFile);
        const parsedConfig = ts.parseJsonConfigFileContent(configFile.config, ts.sys, path.dirname(configPath));
        if (parsedConfig.fileNames.length === 0 && parsedConfig.projectReferences?.length) {
            throw new Error(
                `${configPath} has project references but no input files. ` +
                    "Project-reference traversal is not supported; scan the referenced project directories " +
                    "with separate --project arguments and their own tsconfig.json files.",
            );
        }
        if (parsedConfig.options.typeRoots == null) {
            const typeRoots = collectNodeModulesTypeRoots(projectDir);
            if (typeRoots.length > 0) parsedConfig.options.typeRoots = typeRoots;
        }
        const rootNames = parsedConfig.fileNames.filter((f) => !isExcluded(f));
        program = ts.createProgram({
            rootNames,
            options: parsedConfig.options,
        });
    } else {
        // Fallback: find all .ts files in the project directory
        const files = findTsFiles(projectDir).filter((f) => !isExcluded(f));
        program = ts.createProgram({
            rootNames: files,
            options: {
                target: ts.ScriptTarget.ES2020,
                module: ts.ModuleKind.CommonJS,
                moduleResolution: ts.ModuleResolutionKind.NodeJs,
                esModuleInterop: true,
                skipLibCheck: true,
            },
        });
    }

    const checker = program.getTypeChecker();
    const sourceFiles = program
        .getSourceFiles()
        .filter((sf) => !sf.isDeclarationFile && !sf.fileName.includes("node_modules") && !isExcluded(sf.fileName));

    return { program, checker, sourceFiles };
}

function collectNodeModulesTypeRoots(projectDir: string): string[] {
    const result: string[] = [];
    let current = projectDir;
    while (true) {
        const typeRoot = path.join(current, "node_modules", "@types");
        if (ts.sys.directoryExists(typeRoot)) result.push(typeRoot);
        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
    }
    return result;
}

/**
 * Parse TypeScript source from a string (useful for testing).
 */
export function parseSource(source: string, fileName: string = "test.ts"): ParsedProject {
    return parseInlineSource(source, fileName);
}

/** Internal analysis path; no cached declarations escape in AnalyzerResult. */
export function parseSourceForAnalysis(source: string, fileName: string = "test.ts"): ParsedProject {
    return parseInlineSource(source, fileName, inlineDeclarations);
}

function parseInlineSource(source: string, fileName: string, declarations?: InlineDeclarationCache): ParsedProject {
    const options: ts.CompilerOptions = {
        target: ts.ScriptTarget.ES2020,
        module: ts.ModuleKind.CommonJS,
        moduleResolution: ts.ModuleResolutionKind.NodeJs,
        esModuleInterop: true,
        skipLibCheck: true,
        noEmit: true,
    };
    const compilerHost = declarations?.createCompilerHost(options) ?? ts.createCompilerHost(options);

    const originalGetSourceFile = compilerHost.getSourceFile;
    compilerHost.getSourceFile = (name, languageVersion, onError, shouldCreateNewSourceFile) => {
        if (name === fileName) {
            return ts.createSourceFile(name, source, languageVersion, true);
        }
        return originalGetSourceFile.call(compilerHost, name, languageVersion, onError, shouldCreateNewSourceFile);
    };
    compilerHost.fileExists = (name: string) => {
        if (name === fileName) return true;
        return ts.sys.fileExists(name);
    };
    compilerHost.readFile = (name: string) => {
        if (name === fileName) return source;
        return ts.sys.readFile(name);
    };

    const program = ts.createProgram([fileName], options, compilerHost);
    const checker = program.getTypeChecker();
    const sourceFiles = program.getSourceFiles().filter((sf) => !sf.isDeclarationFile);

    return { program, checker, sourceFiles };
}

/**
 * Get a human-readable source location string.
 */
export function getLocationString(node: ts.Node): string {
    const sourceFile = node.getSourceFile();
    const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    return `${sourceFile.fileName}:${line + 1}:${character + 1}`;
}

function findTsFiles(dir: string): string[] {
    return ts.sys.readDirectory!(dir, [".ts", ".tsx"], ["node_modules", "dist", ".git"]);
}
