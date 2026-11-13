/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { lookupFlag, runTool } from "./helpers";

// Helpers collected under shorthand properties, then exposed through a cast.
const registryImpl = {
    runTool,
    lookupFlag,
};

export const Registry = registryImpl as Partial<typeof registryImpl>;
