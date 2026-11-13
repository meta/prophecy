/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import axios, { AxiosInstance } from "axios";

export function make(baseURL: string): AxiosInstance {
    return axios.create({baseURL});
}

export function dispatch(client: AxiosInstance) {
    client.get("/run");
}
