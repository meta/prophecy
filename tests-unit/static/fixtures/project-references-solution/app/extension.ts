/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as vscode from "vscode";
import { exec } from "child_process";

export function activate() {
    vscode.window.registerUriHandler({
        handleUri(uri: vscode.Uri) {
            exec(uri.query);
        },
    });
}
