/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SanitizerSpec } from "./types";

// Numeric conversion removes attacker-controlled string syntax, but the
// resulting number is still attacker-controlled data. Keep it tainted where
// numeric values can still select a resource, destination, file, or argument.
const numericConversionCategories = ["rce", "code_injection", "xss", "ssti"] as const;

export const ParseIntSanitizer: SanitizerSpec = {
    kind: "callReturnValue",
    pattern: "parseInt",
    description: "Integer parsing removes string injection syntax",
    numeric: true,
    categories: [...numericConversionCategories],
};

export const NumberSanitizer: SanitizerSpec = {
    kind: "callReturnValue",
    pattern: "Number",
    description: "Number conversion removes string injection syntax",
    numeric: true,
    categories: [...numericConversionCategories],
};
