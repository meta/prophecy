/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

export interface PushEvent {
    branch: string;
    retries: string;
}

export function onPush(handler: (event: PushEvent) => void): void {
    void handler;
}
