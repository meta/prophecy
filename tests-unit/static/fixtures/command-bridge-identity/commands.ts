/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { commands } from "vscode";

export const invoke = commands.executeCommand;

export function throughWrapper(value: unknown) {
    return commands.executeCommand("demo.command", value);
}
