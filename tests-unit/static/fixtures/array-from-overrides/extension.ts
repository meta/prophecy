/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
// The imported helper can replace Array.from before the cache reader creates its indices.
// Retain the header-length fallback rather than assuming the local mapper is the implementation.
import * as fs from "fs";
import { mutate } from "./mutator";

export function activate() {
    mutate();
    const header = JSON.parse(fs.readFileSync("/cache/header.json", "utf8"));
    const rows = Array.from({length: header.count}, (_, i) => i);
    fs.readFileSync("/cache/view.s" + rows[0] + ".json");
}
