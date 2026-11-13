/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SourceSpec } from "./types";

/**
 * Resolve callback positions with the plural field taking precedence, even
 * when empty, followed by the variadic range, singleton field, and index zero.
 */
export function callbackArgIndices(source: SourceSpec, argumentCount = 0): number[] {
    if (source.callbackArgIndices) return source.callbackArgIndices;
    if (source.callbackArgStart != null) {
        return Array.from(
            { length: Math.max(0, argumentCount - source.callbackArgStart) },
            (_, index) => source.callbackArgStart! + index,
        );
    }
    return [source.callbackArgIndex ?? 0];
}

/** Parameter-range rules take precedence over the singleton default. */
export function callbackParamIndices(source: SourceSpec, parameterCount: number, restParameterIndex = -1): number[] {
    const start = source.taintParamsFromIndex ?? (source.taintAllParams ? 0 : undefined);
    if (start != null) {
        if (!Number.isInteger(start) || start < 0) return [];
        const first = restParameterIndex >= 0 ? Math.min(start, restParameterIndex) : start;
        return Array.from({ length: Math.max(0, parameterCount - first) }, (_, index) => first + index);
    }
    const requested = source.paramIndex ?? 0;
    if (!Number.isInteger(requested) || requested < 0) return [];
    const index = restParameterIndex >= 0 ? Math.min(requested, restParameterIndex) : requested;
    return index < parameterCount ? [index] : [];
}
