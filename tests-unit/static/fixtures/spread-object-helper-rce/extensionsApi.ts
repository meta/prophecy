/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { Registry } from "./registry";

// Callers reach the helpers through a spread of the registry.
export const Extensions: Partial<typeof Registry> = {
    ...Registry,
};
