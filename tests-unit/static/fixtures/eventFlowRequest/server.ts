/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Scenario: HTTP request data crosses a helper boundary; response and connection metadata are controls.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { createServer } from "node:http";
import { consume } from "./consumer";
createServer((request, response) => {
    consume(request);
    consume(response);
});
