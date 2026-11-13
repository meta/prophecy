/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: Express server vulnerabilities
//
// Demonstrates Prophecy analyzing a non-VS Code project using the Express preset.
// Covers multiple HTTP methods, route parameters, reflected XSS, open redirect,
// path traversal, and sanitization.
import express from "express";
import { exec, execFile, execFileSync, spawn, spawnSync } from "child_process";
import * as fs from "fs";
import * as https from "https";

const app = express();

// VULN: Command injection via query string
app.get("/run", (req: any, res: any) => {
    const cmd = req.query.cmd;
    exec(cmd);
    res.send("done");
});

// VULN: Reflected XSS — req.query.name echoed in response
app.get("/greet", (req: any, res: any) => {
    res.send("Hello " + req.query.name);
});

// VULN: Open redirect — req.query.url controls redirect target
app.get("/redirect", (req: any, res: any) => {
    res.redirect(req.query.url);
});

// VULN: Path traversal — req.params.file controls served file
app.get("/files/:file", (req: any, res: any) => {
    res.sendFile(req.params.file);
});

// VULN: POST body to exec — command injection via POST
app.post("/execute", (req: any, res: any) => {
    exec(req.body.command);
    res.send("executed");
});

// VULN: POST body to spawn options — shell/cwd/env control via JSON body
app.post("/spawn-options", (req: any, res: any) => {
    spawn("/bin/echo", ["ok"], req.body);
    res.send("spawned");
});

// VULN: attacker-controlled destination path (T288945940).
app.post("/write", (req: any, res: any) => {
    fs.writeFile(req.body.path, "fixed", () => {});
    res.send("written");
});

// VULN: Shared Node.js sinks should stay covered by the Express preset.
app.put("/shared-sinks", (req: any, res: any) => {
    const input = req.body.command;
    spawnSync(input, []);
    spawnSync("git", [input]);
    spawnSync("git", [], {shell: input});
    execFile("git", {shell: input});
    execFileSync(input, []);
    execFileSync("git", [input]);
    execFileSync("git", [], {shell: input});
    new Function(input);
    https.request(input);
    res.send("checked");
});

// VULN: app.all — attacker-reachable via any HTTP method
app.all("/admin", (req: any, res: any) => {
    exec(req.query.action);
    res.send("done");
});

// SAFE: parseInt strips the command injection payload.
// parseInt("7; rm -rf /") → 7, so exec("kill -9 7") is safe.
// Numeric conversion is scoped to syntax-bearing sink categories, so the
// value remains tainted for destinations and other non-string-injection uses.
app.get("/safe/kill", (req: any, res: any) => {
    const pid = parseInt(req.query.pid);
    exec("kill -9 " + pid);
    res.send("killed");
});

// SAFE: hardcoded redirect target
app.get("/home", (req: any, res: any) => {
    res.redirect("/dashboard");
});

app.listen(3000);
