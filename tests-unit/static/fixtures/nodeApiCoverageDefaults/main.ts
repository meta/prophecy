/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { make, dispatch } from "./helpers";

export function main() {
    dispatch(make(process.env.INPUT!));
    dispatch(make("https://fixed.test"));
}
