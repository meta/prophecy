/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Scenario: normal next() continuation carries request-derived locals into an imported route handler.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import express from "express";
import { stash, consume } from "./handlers";
const app = express();
app.use((req, res, next) => { stash(req, res); next(); });
app.get("/run", consume);
