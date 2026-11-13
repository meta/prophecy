/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Scenario: selected-path reads are access traces; their contents still reach exec, with fixed-path controls.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";
import * as fs from "node:fs";
import { exec } from "node:child_process";

export async function activate() {
    const selected = await vscode.window.showInputBox();
    exec(fs.readFileSync(selected!, "utf8"));
    fs.readFile(selected!, "utf8", (error, data) => exec(data));
    fs.createReadStream(selected!).on("data", chunk => exec(chunk.toString()));
    fs.writeFileSync("/fixed/cache.json", selected!);

    // Constant paths and unrelated local reads are negative path controls, not
    // claims that file contents or the deployed application are safe.
    fs.readFileSync("/fixed/input.txt", "utf8");
    fs.readFile("/fixed/input.txt", () => {});
    fs.createReadStream("/fixed/input.txt");
    const local = { readFileSync(value: unknown) { return "fixed"; } };
    local.readFileSync(selected);
}
