/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: workspace config → promisified exec in another module (T293393476)
//
// A malicious workspace overrides "demo.toolPath" with shell metacharacters.
// The extension builds a CLI command string from it on activation and runs it
// through `promisify(exec)`, exported from a shared helper module.
//
// Taint flow:
//   activate() → Loader.load() → config.get("toolPath") → execAsync(command)
import * as vscode from "vscode";
import { Loader } from "./loader";

export function activate(context: vscode.ExtensionContext) {
    const loader = new Loader();
    loader.load();
}
