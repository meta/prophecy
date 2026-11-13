/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SourceSpec } from "./types";

// IncomingMessage also holds sockets and server state, not just request data.
export const HttpRequestPropertyPaths = [
    ["url"],
    ["method"],
    ["headers"],
    ["rawHeaders"],
    ["trailers"],
    ["rawTrailers"],
];

// Body readers are only tainted when reached through an incoming Request.
// In particular, Response.text() and a locally constructed Request stay clean.
export const WebRequestPropertyPaths = [
    ["json"],
    ["text"],
    ["formData"],
    ["arrayBuffer"],
    ["blob"],
    ["url"],
    ["method"],
    ["headers"],
    ["body"],
];

export const HttpRequestSources: SourceSpec[] = ["http", "https"].map((module) => ({
    kind: "parameter",
    pattern: `${module}.createServer.request`,
    description: "Incoming HTTP request data (attacker-controlled)",
    callbackRegistration: `${module}.createServer`,
    callbackMatch: "api",
    callbackArgIndices: [0, 1],
    paramIndex: 0,
    paramPropertyPaths: HttpRequestPropertyPaths,
    taintAllProperties: true,
    callbackParameterTypes: { 0: "http.IncomingMessage", 1: "http.ServerResponse" },
}));
