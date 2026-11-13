/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Scenario: request data reaches execution; close-event, socket and server metadata are negative controls.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { exec } from "child_process";
export function consume(stream: any) {
    stream.on("data", (payload: string) => {
        const command = payload;
        exec(command);
    });
    stream.on("close", (metadata: string) => exec(metadata));
    exec(stream.socket);
    exec(stream.server);
}
