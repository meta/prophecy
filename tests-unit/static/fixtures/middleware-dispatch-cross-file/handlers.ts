/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Scenario: imported helpers share response locals without introducing an independent source.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { exec } from "child_process";
export function stash(req, res) { res.locals.command = req.query.command; }
export function consume(req, res) { exec(res.locals.command); }
