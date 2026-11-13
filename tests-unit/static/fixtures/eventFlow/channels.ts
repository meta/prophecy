/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { exec } from "child_process";

export function makeBus() { return new EventEmitter(); }
export function makeStream() { return new PassThrough(); }
export function listen(bus: EventEmitter) {
    bus.on("command", makeListener());
}
function makeListener() {
    return (value: string) => { const command = value; exec(command); };
}
export function produce(bus: EventEmitter, value: string) { bus.emit("command", value); }
export function write(stream: PassThrough, value: string) { stream.write(value); }
export function consume(stream: PassThrough) {
    stream.on("data", value => { const command = value; exec(command); });
}
