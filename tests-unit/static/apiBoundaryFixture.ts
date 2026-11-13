/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export function apiBoundaryFixture(files: Record<string, string>, declarations: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-apiBoundary-"));
    fs.writeFileSync(
        path.join(dir, "tsconfig.json"),
        JSON.stringify({
            compilerOptions: {
                target: "es2020",
                module: "commonjs",
                moduleResolution: "node",
                esModuleInterop: true,
                skipLibCheck: true,
                strict: false,
                types: [],
                noEmit: true,
            },
            include: ["*.ts"],
        }),
    );
    fs.writeFileSync(path.join(dir, "api.d.ts"), declarations);
    for (const [name, content] of Object.entries(files)) {
        fs.writeFileSync(path.join(dir, name), content);
    }
    return dir;
}
