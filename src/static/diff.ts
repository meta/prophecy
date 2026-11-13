/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as path from "path";
import { analyze, AnalyzerResult, detectSpec, inferSappProjectName } from "./analyzer";
import { formatFindings, formatFindingsJSON, formatFindingsMermaid } from "./reporter";
import { formatFindingsLint, generateFixes } from "./fix";
import { TaintFinding, TaintSpec } from "./spec/types";
import { createAnalysisMetrics, mergeAnalysisMetrics } from "./metrics";
import {
    getSaplingRevision,
    normalizeRepoRelativePath,
    parseUnifiedDiffPaths,
    runSaplingCommand,
} from "./sourceControl";
import { Internal } from "./Internal";
import { generateSappMetadata, SappMetadata } from "./sappFormatter";
import { deduplicateFindings } from "./findingUtils";

export interface DiffScreeningOptions {
    diff?: string;
    diffVersion?: string;
    patchFile?: string;
    repoRoot?: string;
    spec?: TaintSpec;
    maxDepth?: number;
    requireTypes?: boolean;
    outputFormat?: "text" | "json" | "mermaid" | "lint" | "sapp-json";
    analysisDebug?: boolean;
    sappProject?: string;
    sappCommit?: string;
    progressReporter?: (line: string) => void;
}

export async function analyzeDiffScreening(options: DiffScreeningOptions): Promise<AnalyzerResult> {
    const repoRoot = await resolveRepoRoot(options.repoRoot);
    const changedRelativePaths = await resolveChangedPaths(options);
    const changedAbsolutePaths = new Set(changedRelativePaths.map((filePath) => path.resolve(repoRoot, filePath)));
    const changedTsPaths = [...changedAbsolutePaths].filter(isTypeScriptFile);
    const projectDirs = [...inferProjectDirs(changedTsPaths, repoRoot)];
    const projectSpecs = new Map(projectDirs.map((projectDir) => [projectDir, options.spec ?? detectSpec(projectDir)]));
    const sappMetadata = await buildSappMetadata(
        options.outputFormat,
        repoRoot,
        projectDirs,
        options.sappProject,
        options.sappCommit,
    );

    if (projectDirs.length === 0) {
        return {
            findings: [],
            formattedOutput: await formatOutput([], options.outputFormat, repoRoot, options.spec ?? detectSpec()),
            entryPointCount: 0,
            cacheHits: 0,
            metrics: createAnalysisMetrics({
                enableDebug: options.analysisDebug,
            }),
            warnings: [],
            skippedEntryPoints: [],
            syntaxErrors: [],
            ...(sappMetadata ? { sappMetadata } : {}),
            ...(options.outputFormat === "sapp-json" ? { sappRepoRoot: repoRoot } : {}),
        };
    }

    // Prefix per-project progress lines so callers can disambiguate
    // when a diff touches multiple TS projects (each with its own
    // tsconfig.json, e.g. several extensions under
    // xplat/vscode/vscode-extensions/).
    const wrapReporter = (projectDir: string) =>
        options.progressReporter
            ? (line: string) => options.progressReporter!(`[${path.basename(projectDir)}] ${line}`)
            : undefined;
    const projectResults = await Promise.all(
        projectDirs.map((projectDir) =>
            analyze({
                projectDir,
                spec: projectSpecs.get(projectDir),
                maxDepth: options.maxDepth,
                requireTypes: options.requireTypes,
                outputFormat: "json",
                analysisDebug: options.analysisDebug,
                findingFilter: (finding) => findingTouchesChangedFile(finding, changedAbsolutePaths),
                progressReporter: wrapReporter(projectDir),
            }),
        ),
    );

    const filteredFindings = deduplicateFindings(projectResults.flatMap((result) => result.findings));

    const formattedOutput = await formatOutput(filteredFindings, options.outputFormat, repoRoot, (finding) =>
        specForFinding(finding, projectDirs, projectSpecs),
    );

    return {
        findings: filteredFindings,
        formattedOutput,
        entryPointCount: projectResults.reduce((sum, result) => sum + result.entryPointCount, 0),
        cacheHits: projectResults.reduce((sum, result) => sum + result.cacheHits, 0),
        metrics: mergeAnalysisMetrics(projectResults.map((result) => result.metrics)),
        warnings: [...new Set(projectResults.flatMap((result) => result.warnings))],
        typeEnvironmentWarning:
            projectResults
                .map((result) => result.typeEnvironmentWarning)
                .filter((warning): warning is string => warning != null)
                .join("\n") || undefined,
        skippedEntryPoints: projectResults.flatMap((result) => result.skippedEntryPoints),
        syntaxErrors: [...new Set(projectResults.flatMap((result) => result.syntaxErrors))],
        ...(sappMetadata ? { sappMetadata } : {}),
        ...(options.outputFormat === "sapp-json" ? { sappRepoRoot: repoRoot } : {}),
    };
}

async function buildSappMetadata(
    outputFormat: "text" | "json" | "mermaid" | "lint" | "sapp-json" | undefined,
    repoRoot: string,
    projectDirs: string[],
    sappProject?: string,
    sappCommit?: string,
): Promise<SappMetadata | undefined> {
    if (outputFormat !== "sapp-json") {
        return undefined;
    }

    const commit = sappCommit ?? (await getSaplingRevision(repoRoot));
    return generateSappMetadata(inferDiffSappProjectName(projectDirs, sappProject), commit);
}

function inferDiffSappProjectName(projectDirs: string[], sappProject?: string): string {
    if (sappProject) {
        return sappProject;
    }

    if (projectDirs.length === 1) {
        return inferSappProjectName({ projectDir: projectDirs[0] });
    }

    return "unknown";
}

function specForFinding(finding: TaintFinding, projectDirs: string[], projectSpecs: Map<string, TaintSpec>): TaintSpec {
    const projectDir = containingProjectDir(
        [finding.sinkLocation.fileName, finding.sourceLocation.fileName],
        projectDirs,
    );
    if (projectDir) {
        return projectSpecs.get(projectDir) ?? detectSpec(projectDir);
    }

    return projectSpecs.values().next().value ?? detectSpec();
}

function containingProjectDir(fileNames: string[], projectDirs: string[]): string | undefined {
    let best: string | undefined;
    for (const fileName of fileNames) {
        const absFile = path.resolve(fileName);
        for (const projectDir of projectDirs) {
            const absProjectDir = path.resolve(projectDir);
            if (
                (absFile === absProjectDir || absFile.startsWith(absProjectDir + path.sep)) &&
                (best == null || absProjectDir.length > best.length)
            ) {
                best = absProjectDir;
            }
        }
    }
    return best;
}

async function formatOutput(
    findings: TaintFinding[],
    outputFormat: "text" | "json" | "mermaid" | "lint" | "sapp-json" | undefined,
    repoRoot: string,
    spec: TaintSpec | ((finding: TaintFinding) => TaintSpec),
): Promise<string> {
    const getSpec = typeof spec === "function" ? spec : () => spec;
    if (outputFormat === "lint" || outputFormat === "sapp-json") {
        const fileContents = new Map<string, string>();
        for (const finding of findings) {
            const sinkFile = finding.sinkLocation.fileName;
            if (!fileContents.has(sinkFile) && fs.existsSync(sinkFile)) {
                fileContents.set(sinkFile, fs.readFileSync(sinkFile, "utf-8"));
            }
        }
        generateFixes(findings, fileContents, (finding) => getSpec(finding).fixStrategies);
        if (outputFormat === "lint") {
            return formatFindingsLint(findings, fileContents, repoRoot, (finding) => getSpec(finding).fixStrategies);
        }

        // SAPP output is streamed by index.ts from the mutated findings; this
        // pass only attaches fixes.
        return "";
    }

    if (outputFormat === "json") {
        return formatFindingsJSON(findings);
    }

    if (outputFormat === "mermaid") {
        const rev = await getSaplingRevision(repoRoot);
        return formatFindingsMermaid(findings, repoRoot, rev);
    }

    const rev = await getSaplingRevision(repoRoot);
    return formatFindings(findings, repoRoot, rev);
}

function findingTouchesChangedFile(finding: TaintFinding, changedFiles: Set<string>): boolean {
    const locations = [
        finding.sourceLocation.fileName,
        finding.sinkLocation.fileName,
        ...finding.propagationChain.map((step) => step.location.fileName),
    ];

    return locations.some((fileName) => changedFiles.has(path.resolve(fileName)));
}

function inferProjectDirs(changedTsPaths: string[], repoRoot: string): Set<string> {
    const projectDirs = new Set<string>();

    for (const filePath of changedTsPaths) {
        const projectDir = findNearestProjectDir(filePath, repoRoot);
        if (projectDir) {
            projectDirs.add(projectDir);
        }
    }

    return projectDirs;
}

function findNearestProjectDir(filePath: string, repoRoot: string): string | undefined {
    const root = path.resolve(repoRoot);
    let currentDir = path.dirname(filePath);
    let packageDir: string | undefined;

    while (currentDir === root || currentDir.startsWith(root + path.sep)) {
        if (fs.existsSync(path.join(currentDir, "tsconfig.json"))) {
            return currentDir;
        }
        if (!packageDir && fs.existsSync(path.join(currentDir, "package.json"))) {
            packageDir = currentDir;
        }
        if (currentDir === root) {
            break;
        }
        currentDir = path.dirname(currentDir);
    }

    return packageDir;
}

function isTypeScriptFile(filePath: string): boolean {
    return /\.(ts|tsx)$/.test(filePath);
}

async function resolveRepoRoot(explicitRepoRoot?: string): Promise<string> {
    if (explicitRepoRoot) {
        return path.resolve(explicitRepoRoot);
    }

    const stdout = await runSaplingCommand(["root"]);
    return stdout.trim();
}

async function resolveChangedPaths(options: DiffScreeningOptions): Promise<string[]> {
    if (options.patchFile) {
        const patch = fs.readFileSync(options.patchFile, "utf-8");
        return parseUnifiedDiffPaths(patch);
    }

    if (!options.diff) {
        throw new Error("Diff screening requires either diff or patchFile");
    }

    if (!Internal.fetchDiffChangedPaths) {
        throw new Error("--diff is not supported in this build; use --patch-file instead");
    }
    const changedPaths = await Internal.fetchDiffChangedPaths(options.diff, options.diffVersion);
    return changedPaths.map(normalizeRepoRelativePath);
}
