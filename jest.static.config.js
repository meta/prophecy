/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

const os = require("os");

module.exports = {
    roots: ["./tests-unit/static"],
    // Each worker builds TypeScript programs; host CPU counts can exceed the memory budget.
    maxWorkers: Math.max(1, Math.min(4, (os.availableParallelism?.() ?? os.cpus().length) - 1)),
    testTimeout: 30000,
    transform: {
        "^.+\\.tsx?$": "ts-jest",
    },
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
};
