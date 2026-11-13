/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: HTTP server RCE via open port
//
// Models an extension that runs a local HTTP server, such as a debugging
// helper, and executes request data. This reduced fixture listens on all
// interfaces and passes req.url to exec without authentication or an origin
// check. It does not parse a request body or test network reachability.
//
// Taint flow:
//   http.createServer((req, res) => ...) → req.url → exec(req.url)
import * as http from "http";
import { exec } from "child_process";

export function activate() {
    const server = http.createServer((req, res) => {
        // Attacker-controlled request URL flows directly to exec
        exec(req.url);
        res.end();
    });
    server.listen(0, "0.0.0.0");
}
