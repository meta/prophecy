/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { apiBoundaryFixture } from "./apiBoundaryFixture";

const declarations = `
declare module "child_process" {
    export function exec(command: string): void;
}
declare module "http" {
    export interface IncomingMessage {
        url: string; method: string; headers: Record<string, string>;
        socket: {localAddress: string};
    }
    export interface ServerResponse {statusCode: number; statusMessage: string;}
    export function createServer(handler: (req: IncomingMessage, res: ServerResponse) => void): void;
    export function createServer(options: object, handler: (req: IncomingMessage, res: ServerResponse) => void): void;
}
declare module "https" {
    export function createServer(options: object, handler: (req: import("http").IncomingMessage, res: import("http").ServerResponse) => void): void;
}
`;

export function httpRequestCoverageFixture(files: Record<string, string>): string {
    return apiBoundaryFixture(files, declarations);
}
