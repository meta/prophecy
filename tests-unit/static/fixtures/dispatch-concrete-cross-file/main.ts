/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { Runner, makeRunner } from "./runners";
declare function register(callback: (input: string) => void): void;
function invoke(runner: Runner, input: string) { runner.run(input); }
register(input => invoke(makeRunner(), input));
