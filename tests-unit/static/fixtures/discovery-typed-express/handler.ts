/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Scenario: an imported typed handler consumes request-derived data carried through response locals.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import {Handler} from "express";
import {exec} from "child_process";
export const consume: Handler = (_req, response) => { exec(response.locals.command); };
