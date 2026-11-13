/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as path from "path";
import * as ts from "typescript";
import { SettingScope } from "./spec/types";

const SCOPES: ReadonlySet<string> = new Set<SettingScope>([
    "application",
    "machine",
    "window",
    "resource",
    "language-overridable",
    "machine-overridable",
]);

/**
 * How few settings files can supply a scope's value. `application` comes only
 * from user settings and `machine` also from remote Machine settings; every
 * other scope also accepts the workspace's `.vscode/settings.json`.
 */
function restriction(scope: SettingScope): number {
    return scope === "application" ? 2 : scope === "machine" ? 1 : 0;
}

/**
 * Setting scopes declared in `contributes.configuration` by the extension
 * manifests (`package.json`) in the directories that hold the program's
 * source files and their ancestors.
 */
export class SettingScopes {
    private readonly scopes = new Map<string, SettingScope>();
    private readonly resolved = new Map<string, SettingScope | undefined>();

    static fromSourceFiles(sourceFiles: readonly ts.SourceFile[]): SettingScopes {
        const index = new SettingScopes();
        const visited = new Set<string>();
        for (const file of sourceFiles) {
            if (file.isDeclarationFile || file.fileName.split(/[\\/]/).includes("node_modules")) continue;
            let dir = path.dirname(file.fileName);
            while (!visited.has(dir)) {
                visited.add(dir);
                index.addManifest(path.join(dir, "package.json"));
                const parent = path.dirname(dir);
                if (parent === dir) break;
                dir = parent;
            }
        }
        return index;
    }

    /**
     * The scope that decides which settings files supply `key`: its declared
     * scope; for an object whose keys are declared individually, the least
     * restrictive of them; otherwise the scope of its nearest declared
     * ancestor, for a property read from an object setting.
     */
    scopeOf(key: string): SettingScope | undefined {
        if (!this.resolved.has(key)) this.resolved.set(key, this.resolve(key));
        return this.resolved.get(key);
    }

    private resolve(key: string): SettingScope | undefined {
        let scope = this.scopes.get(key);
        const prefix = `${key}.`;
        for (const [declared, declaredScope] of this.scopes) {
            if (declared.startsWith(prefix) && (scope == null || restriction(declaredScope) < restriction(scope))) {
                scope = declaredScope;
            }
        }
        if (scope != null) return scope;
        for (let end = key.lastIndexOf("."); end > 0; end = key.lastIndexOf(".", end - 1)) {
            const ancestor = this.scopes.get(key.slice(0, end));
            if (ancestor != null) return ancestor;
        }
        return undefined;
    }

    private addManifest(manifestPath: string): void {
        let configuration: unknown;
        try {
            configuration = JSON.parse(fs.readFileSync(manifestPath, "utf-8"))?.contributes?.configuration;
        } catch {
            return;
        }
        for (const section of Array.isArray(configuration) ? configuration : [configuration]) {
            const properties: unknown = section?.properties;
            if (properties == null || typeof properties !== "object") continue;
            for (const [key, property] of Object.entries(properties)) {
                // VS Code treats an omitted or unrecognized scope as `window`.
                const declared: unknown = property?.scope;
                const scope =
                    typeof declared === "string" && SCOPES.has(declared) ? (declared as SettingScope) : "window";
                const existing = this.scopes.get(key);
                // The same key in several manifests: any of them may supply it.
                if (existing == null || restriction(scope) < restriction(existing)) {
                    this.scopes.set(key, scope);
                }
            }
        }
    }
}
