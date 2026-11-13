/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { launch, request, read } from "./helpers";

export function main() {
    launch(process.env.INPUT!);
    request({url: process.env.INPUT});
    read(process.env.INPUT!);
    request({url: "https://fixed.test", data: {url: process.env.INPUT}});
    read("/fixed");
}
