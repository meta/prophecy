/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as ts from "typescript";
import { SettingScopes } from "../../src/static/settingScopes";

describe("SettingScopes", () => {
    let root: string;

    beforeEach(() => {
        root = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-setting-scopes-"));
    });

    afterEach(() => {
        fs.rmSync(root, { recursive: true, force: true });
    });

    function manifest(dir: string, contents: object): void {
        fs.mkdirSync(path.join(root, dir), { recursive: true });
        fs.writeFileSync(path.join(root, dir, "package.json"), JSON.stringify(contents));
    }

    function scopesFor(...files: string[]): SettingScopes {
        return SettingScopes.fromSourceFiles(
            files.map((file) => ts.createSourceFile(path.join(root, file), "", ts.ScriptTarget.Latest)),
        );
    }

    const properties = (props: Record<string, object>) => ({ contributes: { configuration: { properties: props } } });

    it("reads manifests in the source file's directory and its ancestors", () => {
        manifest("ext", properties({ "demo.path": { scope: "machine" } }));
        manifest("ext/src", properties({ "demo.tool": { scope: "application" } }));
        const scopes = scopesFor("ext/src/extension.ts");
        expect(scopes.scopeOf("demo.path")).toBe("machine");
        expect(scopes.scopeOf("demo.tool")).toBe("application");
    });

    it("treats an omitted or unrecognized scope as window", () => {
        manifest("ext", properties({ "demo.a": {}, "demo.b": { scope: "workspace" } }));
        const scopes = scopesFor("ext/extension.ts");
        expect(scopes.scopeOf("demo.a")).toBe("window");
        expect(scopes.scopeOf("demo.b")).toBe("window");
    });

    it("accepts an array of configuration sections", () => {
        manifest("ext", {
            contributes: {
                configuration: [
                    { properties: { "demo.a": { scope: "machine" } } },
                    { properties: { "demo.b": { scope: "application" } } },
                ],
            },
        });
        const scopes = scopesFor("ext/extension.ts");
        expect(scopes.scopeOf("demo.a")).toBe("machine");
        expect(scopes.scopeOf("demo.b")).toBe("application");
    });

    it("gives an object setting the least restrictive scope of the keys under it", () => {
        manifest(
            "ext",
            properties({
                "demo.server.path": { scope: "machine" },
                "demo.server.args": { scope: "application" },
                "demo.other.path": { scope: "machine" },
                "demo.other.enable": {},
            }),
        );
        const scopes = scopesFor("ext/extension.ts");
        expect(scopes.scopeOf("demo.server")).toBe("machine");
        expect(scopes.scopeOf("demo.other")).toBe("window");
    });

    it("gives a property of an object setting the scope of the declared object", () => {
        manifest("ext", properties({ "demo.server": { type: "object", scope: "machine" } }));
        expect(scopesFor("ext/extension.ts").scopeOf("demo.server.path")).toBe("machine");
    });

    it("keeps the least restrictive scope when manifests declare the same key", () => {
        manifest("a", properties({ "demo.path": { scope: "application" } }));
        manifest("b", properties({ "demo.path": {} }));
        expect(scopesFor("a/extension.ts", "b/extension.ts").scopeOf("demo.path")).toBe("window");
    });

    it("ignores manifests inside node_modules and undeclared keys", () => {
        manifest("ext/node_modules/dep", properties({ "dep.path": { scope: "machine" } }));
        const scopes = scopesFor("ext/node_modules/dep/index.ts");
        expect(scopes.scopeOf("dep.path")).toBeUndefined();
        expect(scopes.scopeOf("demo.path")).toBeUndefined();
    });
});
