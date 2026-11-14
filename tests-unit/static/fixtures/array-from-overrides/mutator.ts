/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
// A constructor alias in a separate module exposes a replacement that returns length as element data.
// This keeps the cross-file override control independent of inherited-property source modeling.
export function mutate() {
    const Constructor = globalThis.Array;
    Constructor.from = ((input: {length: unknown}) => [input.length]) as typeof Array.from;
}
