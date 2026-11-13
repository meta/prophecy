/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { spawnSync } from "child_process";
import * as os from "os";
import * as path from "path";

const root = path.resolve(__dirname, "../..");
const jestBin = path.join(path.dirname(require.resolve("jest/package.json")), "bin/jest.js");

function workerCount(args: string[]): number {
    const result = spawnSync(
        process.execPath,
        [jestBin, "--config", "jest.static.config.js", "--showConfig", ...args],
        {
            cwd: root,
            encoding: "utf8",
            timeout: 30000,
        },
    );
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    return JSON.parse(result.stdout).globalConfig.maxWorkers;
}

describe("static test worker budget", () => {
    it("caps the default worker budget without exceeding available CPUs", () => {
        expect(workerCount([])).toBe(Math.max(1, Math.min(4, os.availableParallelism() - 1)));
    });

    it.each([
        [1, 1],
        [2, 1],
        [4, 3],
        [8, 4],
        [176, 4],
    ])("uses %i available CPUs for a %i-worker default", (cpus, workers) => {
        jest.isolateModules(() => {
            jest.doMock("os", () => ({ availableParallelism: () => cpus }));
            expect(require("../../jest.static.config.js").maxWorkers).toBe(workers);
        });
        jest.dontMock("os");
    });

    it("falls back to the logical CPU count when availableParallelism is absent", () => {
        jest.isolateModules(() => {
            jest.doMock("os", () => ({ cpus: () => [{}, {}] }));
            expect(require("../../jest.static.config.js").maxWorkers).toBe(1);
        });
        jest.dontMock("os");
    });

    it("honors an explicit worker override", () => {
        expect(workerCount(["--maxWorkers=7"])).toBe(7);
    });

    it("honors serial execution", () => {
        expect(workerCount(["--runInBand"])).toBe(1);
    });
});
