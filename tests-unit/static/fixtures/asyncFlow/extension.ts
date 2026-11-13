/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { exec } from "child_process";
import { resolvePayload, makeGetter, runPromise, runMapped, runAll, Command, identity, select } from "./stages";

export function activate() {
    resolvePayload(process.env.INPUT!).then(runPromise);
    runMapped(["fixed"].map(makeGetter(process.env.INPUT!))[0]);
    select([new Command(process.env.INPUT!)].map(identity))[0].run();
    Promise.all([Promise.resolve("fixed"), resolvePayload(process.env.INPUT!)])
        .then(([safe, dirty]) => { exec(safe); runAll(dirty); });

    // Callback results discard input; filter must not substitute its predicate's result.
    Promise.resolve(process.env.INPUT!).then(() => "fixed").then(value => exec(value));
    exec([process.env.INPUT!].map(() => "fixed")[0]);
    exec(["fixed"].filter(makeGetter(process.env.INPUT!))[0]);
    select([new Command("fixed")].map(identity))[0].run();
}
