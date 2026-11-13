/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// URI handler that dispatches deeplink params through free functions.
import * as vscode from "vscode";
import { runCommand } from "./commandRunner";

export class DeeplinkRouter implements vscode.UriHandler {
    handleUri(uri: vscode.Uri) {
        const params = uri.query;
        runCommand(params);
    }
}
