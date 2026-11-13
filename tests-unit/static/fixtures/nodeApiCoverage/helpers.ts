/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import execa from "execa";
import axios, { AxiosRequestConfig } from "axios";
import { readFile } from "node:fs";

export function launch(value: string) {
    execa("git", [value]);
}

export function request(config: AxiosRequestConfig) {
    axios.request(config);
}

export function read(file: string) {
    readFile(file, () => {});
}
