/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { exec } from "child_process";

const bus = new EventEmitter();
const stream = new PassThrough();
const unrelated = new EventEmitter();
export function listenShared() {
    bus.on("command", value => { const command = value; exec(command); });
    stream.on("data", value => { const command = value; exec(command); });
    unrelated.on("command", value => exec(value));
}
export function produceShared(value: string) {
    bus.emit("command", value);
    stream.write(value);
    unrelated.emit("command", "fixed");
}
