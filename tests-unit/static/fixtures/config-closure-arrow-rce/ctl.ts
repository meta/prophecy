/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Sinks reached from workspace configuration through closure, default
// parameter, and parameter property shapes.
import { execFile, spawn } from "child_process";

// Control: function declaration
export function runCtl(ctlPath: string, args: string[]) {
    execFile(ctlPath, args);
}

// A: exported const arrow function
export const spawnCtl = (ctlPath: string, args: string[]) => spawn(ctlPath, args);

// B: sink reachable only through a default-parameter callee
export type Probe = (file: string, args: string[]) => void;
export const defaultProbe: Probe = (file, args) => { execFile(file, args); };
export function checkRequirements(ctlPath: string, probe: Probe = defaultProbe) {
    probe(ctlPath, ["--help"]);
}

// C: property renamed across object hops into a constructor that reads its
//    parameter property by bare name
export class Client {
    constructor(private readonly options: { executable: string }) {
        spawn(options.executable, ["embed"]);
    }
}
export class Pane {
    constructor(private readonly host: { agentPath: string }) {}
    open() { new Client({ executable: this.host.agentPath }); }
}

// D: closure-returned object, destructured; then a field of a helper-built union
type Machine = { kind: "local" } | { kind: "node"; nodeId: string; ctlPath: string };
function parseMachine(key: string, ctlPath: string): Machine {
    return key.startsWith("node:") ? { kind: "node", nodeId: key.slice(5), ctlPath } : { kind: "local" };
}
export class Changes {
    constructor(private readonly ctl: () => { ctlPath: string }) {}
    refresh(key: string) {
        const { ctlPath } = this.ctl();
        execFile(ctlPath, ["node", "list"]);                                   // D1
        const m = parseMachine(key, ctlPath);
        if (m.kind === "node") {
            execFile(m.ctlPath, ["node", "exec", "--", "sh", "-c", "ls"]);        // D2
        }
    }
}
