/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { SourceSpec, TaintSpec } from "./types";
import { NodeSinks } from "./nodeApis";
import { HttpRequestSources } from "./http";
import { NumberSanitizer, ParseIntSanitizer } from "./sanitizers";

const EXPRESS_ROUTE_METHODS = ["get", "post", "put", "delete", "patch", "head", "options", "all"] as const;
const REQUEST_PATHS = [
    ["query"],
    ["params"],
    ["body"],
    ["headers"],
    ["rawHeaders"],
    ["cookies"],
    ["signedCookies"],
    ["url"],
    ["originalUrl"],
    ["baseUrl"],
    ["path"],
    ["hostname"],
    ["ip"],
    ["ips"],
    ["method"],
];

function requestSource(receiver: string, method: string): SourceSpec {
    const routeObject = receiver === "express.Route";
    return {
        kind: "parameter",
        pattern: `${method}.req`,
        description:
            method === "all"
                ? "Express all-methods request object (attacker-controlled)"
                : `Express ${method.toUpperCase()} request object (attacker-controlled)`,
        entryPointDescription: `Callback handler for ${method}`,
        taintAllProperties: true,
        paramPropertyPaths: REQUEST_PATHS,
        callbackRegistration: `${receiver}.${method}`,
        callbackMatch: "api",
        callbackArgStart: routeObject || method === "use" ? 0 : 1,
        callbackParameterTypes: { 0: "express.Request", 1: "express.Response" },
        paramIndex: 0,
        callbackChain: {
            nextParamIndex: 2,
            excludedHandlerArities: [4],
            sharedParamIndices: [0, 1],
            sharedParamProperties: { 1: [["locals"]] },
            role: method === "use" ? "middleware" : "route",
            ...(method === "use" ? { mountReceiverTypes: ["express.Router"] } : {}),
            ...(routeObject ? { receiverPathArgIndex: 0 } : { pathArgIndex: 0 }),
        },
    };
}

/** Express request boundaries and response APIs, with ordered normal middleware. */
export const expressSpec: TaintSpec = {
    entryFunctions: ["main"],
    sources: [
        ...["express.Application", "express.Router"].flatMap((receiver) =>
            [...EXPRESS_ROUTE_METHODS, "use"].map((method) => requestSource(receiver, method)),
        ),
        ...EXPRESS_ROUTE_METHODS.map((method) => requestSource("express.Route", method)),
        ...HttpRequestSources.map((source) => ({
            ...source,
            pattern: "createServer.req",
            entryPointDescription: "Callback handler for createServer",
        })),
        ...["get", "header", "param"].map((method): SourceSpec => ({
            kind: "callReturnValue",
            pattern: `express.Request.${method}`,
            requireAPIIdentity: true,
            description: `HTTP request value read via Express request.${method}`,
            taintAllProperties: true,
        })),
    ],
    sinks: [
        ...NodeSinks,
        {
            kind: "callArgument",
            name: "send",
            pattern: "express.Response.send",
            argPositions: [0],
            requireAPIIdentity: true,
            description: "HTTP response body (reflected XSS risk)",
            severity: "high",
            categories: ["xss"],
        },
        {
            kind: "callArgument",
            name: "http_redirect",
            pattern: "express.Response.redirect",
            argPositions: [0],
            argPositionsByArity: { 2: [1] },
            requireAPIIdentity: true,
            description: "HTTP redirect with attacker-controlled URL (open redirect)",
            severity: "high",
            categories: ["open_redirect"],
        },
        {
            kind: "callArgument",
            name: "render",
            pattern: "express.Response.render",
            argPositions: [0],
            requireAPIIdentity: true,
            description: "Template file selected by attacker-controlled view name (LFI risk)",
            severity: "high",
            categories: ["lfi"],
        },
        {
            kind: "callArgument",
            name: "sendFile",
            pattern: "express.Response.sendFile",
            argPositions: [0],
            requireAPIIdentity: true,
            description: "File serving with attacker-controlled path (LFI risk)",
            severity: "high",
            categories: ["lfi"],
        },
    ],
    sanitizers: [ParseIntSanitizer, NumberSanitizer],
};
