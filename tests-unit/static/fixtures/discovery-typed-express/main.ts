/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Scenario: typed Express aliases share request data; separate receivers and local lookalikes remain isolated.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import {Instance} from "express-ws";
import {exec} from "child_process";
import {consume} from "./handler";
export function install(server: Instance, separate: Instance, path: string): void {
    server.app.use((req, res, next) => { res.locals.command = req.query.command; next(); });
    const application = server.app;
    application.get("/run", consume);
    separate.app.get("/safe", (_req, res) => { exec(res.locals.command); });
    server.app.post(path, req => { exec(req.body.command); });
    const mock = {app: {get(_path: string, _handler: unknown) {}}};
    mock.app.get("/unrelated", (req: any) => { exec(req.query.command); });
}
