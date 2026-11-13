/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { detectSpec } from "../../src/static/analyzer";
import { builtinSpecs, PresetName, presetChoices } from "../../src/static/spec/presets";

function detect(manifest: unknown) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-preset-"));
    try {
        fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify(manifest));
        return detectSpec(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

describe("Built-in preset selection", () => {
    it.each(["electron", "express"] as PresetName[])(
        "selects %s from dependencies or development dependencies",
        (name) => {
            expect(detect({ dependencies: { [name]: "*" } })).toBe(builtinSpecs[name]);
            expect(detect({ devDependencies: { [name]: "*" } })).toBe(builtinSpecs[name]);
        },
    );

    it("recognizes Express declaration dependencies", () => {
        expect(detect({ dependencies: { "@types/express": "*" } })).toBe(builtinSpecs.express);
    });

    it("preserves VS Code priority and fallback, and chooses Electron before Express", () => {
        expect(detect({ engines: { vscode: "*" }, dependencies: { electron: "*", express: "*" } })).toBe(
            builtinSpecs["vscode-extension"],
        );
        expect(detect({ dependencies: { electron: "*", express: "*" } })).toBe(builtinSpecs.electron);
        expect(detect({ dependencies: { "unmodeled-server": "*", express: "*" } })).toBe(builtinSpecs.express);
        expect(detect({ dependencies: { "unmodeled-server": "*" } })).toBe(builtinSpecs["vscode-extension"]);
        expect(detect({})).toBe(builtinSpecs["vscode-extension"]);
    });

    it("exposes every built-in spec to the CLI choices", () => {
        expect(presetChoices).toEqual(["auto", "vscode-extension", "express", "electron", "isl"]);
    });
});
