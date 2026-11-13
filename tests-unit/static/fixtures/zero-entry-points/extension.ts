/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: valid TypeScript with no VS Code entry points
// No activate(), no registerCommand, no registerUriHandler.
// The analyzer should return 0 findings without crashing.

const GREETING = "hello";

function helper(x: number): number {
    return x * 2;
}

interface Config {
    name: string;
    value: number;
}

class Calculator {
    add(a: number, b: number): number {
        return a + b;
    }
}
