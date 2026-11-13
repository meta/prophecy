/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: express.Router() uses the same .get/.post pattern
//
// Taint flow: router.get("/search", (req, res) => ...) → req.query.q → res.send
import express from "express";

const router = express.Router();

// VULN: Reflected XSS via router
router.get("/search", (req: any, res: any) => {
    res.send("Results for: " + req.query.q);
});

export default router;
