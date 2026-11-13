/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import {exec} from "child_process";

declare function register(callback: (input: string) => void): void;
interface Runner {run(input: string): void;}
class Unsafe implements Runner {run(input: string): void {exec(input);}}
class Safe implements Runner {run(_input: string): void {exec("fixed");}}
declare function lookup(): Runner | undefined;

register(input => lookup()?.run(input));
register(input => lookup()!.run(input));
register(input => {
    const known: Runner | undefined = new Safe();
    known?.run(input);
});
