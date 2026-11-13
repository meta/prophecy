/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { TaintSpec } from "./types";
import { vscodeExtensionSpec } from "./vscodeExtension";
import { expressSpec } from "./express";
import { electronSpec } from "./electron";
import { islSpec } from "./isl";

export const builtinSpecs = {
    "vscode-extension": vscodeExtensionSpec,
    express: expressSpec,
    electron: electronSpec,
    isl: islSpec,
} satisfies Record<string, TaintSpec>;

export type PresetName = keyof typeof builtinSpecs;
export type PresetSelection = "auto" | PresetName;
export const presetChoices: readonly PresetSelection[] = ["auto", ...(Object.keys(builtinSpecs) as PresetName[])];
