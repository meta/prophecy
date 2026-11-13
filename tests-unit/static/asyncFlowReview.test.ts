/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import { analyze } from "../../src/static/analyzer";
import { vscodeSpecWithEnvSource } from "./testUtils";

async function review(body: string, declarations = "") {
    const result = await analyze({
        source: `import { exec } from 'child_process'; import { EventEmitter } from 'events';
            ${declarations}
            export async function activate() { ${body} }`,
        fileName: "/src/asyncFlowReview.ts",
        spec: vscodeSpecWithEnvSource,
        maxDepth: 10,
        outputFormat: "text",
    });
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings.filter((finding) => finding.sink.name === "exec");
}

describe("asyncFlow review regressions", () => {
    it.each([
        ["thrown fulfillment", "Promise.resolve(process.env.INPUT).then(x=>{throw x}).catch(x=>exec(x));"],
        ["async throw", "async function fail() { throw process.env.INPUT; } fail().catch(x=>exec(x));"],
        [
            "await rejection",
            "async function fail() { return await Promise.reject(process.env.INPUT); } fail().catch(x=>exec(x));",
        ],
        ["callback undefined default", "Promise.resolve(undefined).then((x=process.env.INPUT)=>exec(x));"],
        ["callback absent default", "Promise.resolve().then((x=process.env.INPUT)=>exec(x));"],
        ["map undefined default", "[undefined].map((x=process.env.INPUT)=>x).map(x=>exec(x));"],
        ["executor fulfillment", "new Promise(resolve=>resolve(process.env.INPUT)).then(x=>exec(x));"],
        ["executor rejection", "new Promise((resolve,reject)=>reject(process.env.INPUT)).catch(x=>exec(x));"],
        ["executor throw", "new Promise(()=>{throw process.env.INPUT}).catch(x=>exec(x));"],
        ["map element overwrite", "const values=['fixed'].map(x=>x); values[0]=process.env.INPUT; exec(values[0]);"],
        [
            "sequential captured fields",
            "const state={command:'fixed'}; const bus=new EventEmitter(); bus.on('run',x=>{state.command=x}); bus.on('run',()=>exec(state.command)); bus.emit('run',process.env.INPUT);",
        ],
        [
            "once before persistent",
            "const state={command:'fixed'}; const bus=new EventEmitter(); bus.once('run',x=>{state.command=x}); bus.on('run',()=>exec(state.command)); bus.emit('run',process.env.INPUT);",
        ],
    ])("propagates %s", async (_name, body) => {
        expect(await review(body)).toHaveLength(1);
    });

    it.each([
        ["throw does not fulfill", "Promise.resolve(process.env.INPUT).then(x=>{throw x}).then(x=>exec(x));"],
        [
            "caught throw",
            "Promise.resolve(process.env.INPUT).then(x=>{try {throw x} catch {return 'fixed'}}).then(x=>exec(x));",
        ],
        ["known defined callback", "Promise.resolve('fixed').then((x=process.env.INPUT)=>exec(x));"],
        ["known defined map", "['fixed'].map((x=process.env.INPUT)=>x).map(x=>exec(x));"],
        [
            "executor first settlement",
            "new Promise((resolve,reject)=>{resolve('fixed');reject(process.env.INPUT)}).catch(x=>exec(x));",
        ],
        [
            "executor ignores late throw",
            "new Promise(resolve=>{resolve('fixed');throw process.env.INPUT}).catch(x=>exec(x));",
        ],
        ["map clean overwrite", "const values=[process.env.INPUT].map(x=>x); values[0]='fixed'; exec(values[0]);"],
        [
            "deferred object write",
            "const state={command:'fixed'}; Promise.resolve(process.env.INPUT).then(x=>{state.command=x}); exec(state.command);",
        ],
        [
            "deferred class write",
            "class State {command='fixed'} const state=new State(); Promise.resolve(process.env.INPUT).then(x=>{state.command=x}); exec(state.command);",
        ],
        [
            "chronological listeners",
            "const state={command:'fixed'}; const bus=new EventEmitter(); bus.on('run',()=>exec(state.command)); bus.once('run',x=>{state.command=x}); bus.emit('run',process.env.INPUT);",
        ],
    ])("keeps %s clean", async (_name, body) => {
        expect(await review(body)).toHaveLength(0);
    });

    it("isolates module event state in mutually exclusive branches through helpers", async () => {
        const declarations = `const bus=new EventEmitter();
            function subscribe() { bus.on('run',x=>exec(x)); }
            function emit(value: string) { bus.emit('run',value); }`;
        expect(
            await review("if(process.env.MODE) subscribe(); else emit(process.env.INPUT);", declarations),
        ).toHaveLength(0);
    });
    it("retains module listener effects from a helper branch", async () => {
        const declarations = `const bus=new EventEmitter();
            function subscribe() { if(process.env.MODE) bus.on('run',x=>exec(x)); }`;
        expect(await review("subscribe(); bus.emit('run',process.env.INPUT);", declarations)).toHaveLength(1);
    });
});
