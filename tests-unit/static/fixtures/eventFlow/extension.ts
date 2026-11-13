/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { makeBus, makeStream, listen, produce, write, consume } from "./channels";
import { listenShared, produceShared } from "./shared";

export function activate() {
    listenShared();
    produceShared(process.env.INPUT!);
    const bus = makeBus();
    listen(bus);
    produce(bus, process.env.INPUT!);
    const buffered = makeStream();
    write(buffered, process.env.INPUT!);
    consume(buffered);
    const flowing = makeStream();
    consume(flowing);
    write(flowing, process.env.INPUT!);

    const unrelatedBus = makeBus();
    listen(unrelatedBus);
    produce(makeBus(), process.env.INPUT!);
    produce(unrelatedBus, "fixed");
    const unrelatedStream = makeStream();
    consume(unrelatedStream);
    write(makeStream(), process.env.INPUT!);
    write(unrelatedStream, "fixed");
}
