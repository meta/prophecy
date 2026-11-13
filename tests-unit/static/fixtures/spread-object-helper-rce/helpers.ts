/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { execFile } from "child_process";

export function runTool(args: string[], cwd: string) {
    return execFile("tool", args, { cwd });
}

export function lookupFlag(name: string): boolean {
    return name.length > 0;
}
