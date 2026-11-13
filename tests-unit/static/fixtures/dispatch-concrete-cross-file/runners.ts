/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { exec } from "child_process";
export class Runner { run(input: string) { exec("fixed"); } }
class UnsafeRunner extends Runner {
    run(input: string) {
        const command = input;
        exec(command);
    }
}
export function makeRunner(): Runner { return new UnsafeRunner(); }
