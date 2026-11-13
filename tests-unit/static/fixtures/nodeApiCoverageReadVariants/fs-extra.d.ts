/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// fs-extra 11.3.2 lib/fs/index.js wraps fs.readFile with
// universalify 2.0.1 fromCallback: callback supplied => void, omitted => Promise.
// Its cloned graceful-fs exports also retain the native fs.promises namespace.
declare module "fs-extra" {
    export function readFile(path: string): Promise<Buffer>;
    export function readFile(path: string, encoding: "utf8"): Promise<string>;
    export function readFile(path: string, options: {encoding: "utf8"}): Promise<string>;
    export function readFile(path: string, callback: (error: Error | null, data: Buffer) => void): void;
    export function readFile(path: string, encoding: "utf8", callback: (error: Error | null, data: string) => void): void;
    export const promises: typeof import("node:fs/promises");
}
