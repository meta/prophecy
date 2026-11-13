/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Parses and forwards a command to the terminal manager.
import { executeInTerminal } from "./terminal";

export function runCommand(raw: string) {
    const cmd = prepareCommand(raw);
    executeInTerminal(cmd);
}

function prepareCommand(input: string): string {
    // Wraps the command in a shell invocation — still tainted!
    return "bash -c " + input;
}
