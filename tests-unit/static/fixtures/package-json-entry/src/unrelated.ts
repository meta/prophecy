/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Not a framework entry point and not called by the extension. Its untainted
// parameter is a negative control; package.json main does not exclude this file.
import { exec } from "child_process";

export function decoy(cmd: string) {
    exec(cmd);
}
