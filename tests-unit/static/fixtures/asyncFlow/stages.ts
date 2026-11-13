/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { exec } from "child_process";

export function resolvePayload(value: string) {
    return Promise.resolve(value);
}
export function makeGetter(value: string) {
    return () => value;
}
export function runPromise(value: string) {
    const command = value;
    exec(command);
}
export function runMapped(value: string) {
    const command = value;
    exec(command);
}
export function runAll(value: string) {
    const command = value;
    exec(command);
}
export class Command {
    constructor(private command: string) {}
    run() { const command = this.command; exec(command); }
}
export function identity<T>(value: T): T { return value; }
export function select<T>(values: T[]): T[] { return values.filter(() => true); }
