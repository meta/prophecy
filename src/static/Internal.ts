/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// @fb-only: import { InternalImports } from "./facebook/InternalImports";
import { SinkSpec, SourceSpec } from "./spec/types";

// This should be the only file using fb-only imports. `removeInternalFiles.sh`
// (and the open source mirror) replaces every `// @fb-only` line with a bare
// comment and deletes all facebook/ directories.
//
// The VS Code spec reads `Internal` while its module loads, so nothing the
// internal implementation imports may import the analyzer or a spec.

/** Internal-only (non-OSS) integrations. */
export interface InternalApi {
    /** URL for a repo-relative file location, or undefined for no link. */
    codeLinkUrl(repoRoot: string, rev: string, relativePath: string, line: number): string | undefined;
    /** Repo-relative paths changed by the code review `diff` (`--diff`). */
    fetchDiffChangedPaths(diff: string, diffVersion?: string): Promise<string[]>;
    sappRepositoryName(): string;
    sappJobInstance(): string | undefined;
    /** Sinks in internal extensions' commands, added to the VS Code spec. */
    vscodeExtensionSinks: SinkSpec[];
    /** Source boundaries in internal extension frameworks. */
    vscodeExtensionSources: SourceSpec[];
}

/**
 * API for accessing internal (non-OSS) features / functions.
 * In OSS builds, all properties are undefined.
 */
export const Internal: Partial<InternalApi> = {
    // @fb-only: ...InternalImports,
};
