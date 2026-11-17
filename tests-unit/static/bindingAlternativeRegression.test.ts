/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";

async function scan(body: string) {
    const result = await analyze({
        source: `import * as vscode from "vscode"; import {exec, execFile} from "child_process";
            declare const flag: boolean;
            declare function opaque(value?: unknown): any;
            export function activate() {
                vscode.window.registerUriHandler({handleUri(uri: vscode.Uri) { ${body} }});
            }`,
        fileName: "/src/binding-alternatives.ts",
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("Binding alternatives", () => {
    it.each([
        "const options={process:{command:uri.query,cwd:'fixed'}}; exec(Object.values(options).join(' '));",
        "const options={process:{command:uri.query,cwd:'fixed'}}; exec(Object.entries(options).flat().join(' '));",
        "const {command}=JSON.parse(uri.query)||{}; exec(command);",
        "const {command}=JSON.parse(uri.query)??{}; exec(command);",
        "const {command}=flag?JSON.parse(uri.query):{}; exec(command);",
        "const {command}=flag?{}:JSON.parse(uri.query); exec(command);",
        "const {command}=flag?{command:'fixed'}:JSON.parse(uri.query); exec(command);",
        "const value=JSON.parse(uri.query)||{}; const alias=value; const {command}=alias; exec(command);",
        "function get(){return flag?JSON.parse(uri.query):{};} const {command}=get(); exec(command);",
        "const {nested:{command}}=JSON.parse(uri.query)||{nested:{command:'fixed'}}; exec(command);",
        "const {command=uri.query}=flag?opaque():{command:'fixed'}; exec(command);",
        "const value=flag?{nested:{command:'fixed'}}:JSON.parse(uri.query); exec(value.nested.command);",
        "const value=flag?{nested:{command:'fixed'}}:JSON.parse(uri.query); const alias=value.nested; exec(alias.command);",
        "const value=flag?[[{command:'fixed'}]]:JSON.parse(uri.query); exec(value[0][0].command);",
        "const [command=uri.query]=flag?opaque():['fixed']; exec(command);",
        "const [command]=JSON.parse(uri.query)||[]; exec(command);",
        "const [command]=JSON.parse(uri.query)||['fixed']; exec(command);",
        "const [safe,...rest]=JSON.parse(uri.query)||['fixed','fixed']; exec(rest[0]);",
        "const {nested,...rest}=JSON.parse(uri.query)||{nested:{safe:'fixed'}}; exec(rest.command);",
        "const {command}=flag?{command:uri.query}:{}; exec(command);",
        "const box=flag?{command:'fixed'}:JSON.parse(uri.query); box.command=uri.query; const {command}=box; exec(command);",
    ])("retains reachable input through %s", async (body) => {
        expect((await scan(body)).filter((finding) => finding.sink.name === "exec")).toHaveLength(1);
    });

    it.each([
        "function choose(nodes,count){return nodes[Math.floor(nodes.length/count)];} exec(choose([{name:'fixed'}],uri.query).name);",
        "const {command}=flag?{command:'fixed'}:{}; exec(command);",
        "const {command='fixed'}=flag?{command:'fixed'}:{}; exec(command);",
        "const {safe}=flag?{safe:'fixed',command:uri.query}:{safe:'fixed'}; exec(safe);",
        "const [command]=flag?['fixed',uri.query]:['fixed']; exec(command);",
        "const box={command:'fixed',other:uri.query}; const {command}=box; exec(command);",
        "const box=flag?{command:'fixed'}:JSON.parse(uri.query); box.command='fixed'; const {command}=box; exec(command);",
    ])("preserves precise clean controls through %s", async (body) => {
        expect((await scan(body)).filter((finding) => finding.sink.name === "exec")).toHaveLength(0);
    });

    it.each([
        "const value={command:uri.query,args:['fixed']}; const {command,args}=value; execFile('fixed',args);",
        "function params(command:string,args:string[]){return {command,args};} const {args}=params(uri.query,['fixed']); execFile('fixed',args);",
        "const existing=opaque(); const id='fixed'; const records={...existing,[id]:{title:uri.query}}; for(const [key] of Object.entries(records)){exec(key);}",
        "for(const value of Object.values({[uri.query]:'fixed'})){exec(value);}",
        "for(const key of Object.keys({fixed:uri.query})){exec(key);}",
        "const records={fixed:{title:uri.query}}; for(const [key] of Object.entries(records)){exec(key);}",
        "const id='fixed'; const records={[id]:{title:uri.query}}; for(const [key] of Object.entries(records)){exec(key);}",
        "const entries=Object.entries; for(const [key] of entries({fixed:uri.query})){exec(key);}",
    ])("keeps unrelated operands clean through %s", async (body) => {
        expect(await scan(body)).toHaveLength(0);
    });

    it.each([
        "for(const key of Object.keys({[uri.query]:'fixed'})){exec(key);}",
        "for(const value of Object.values({fixed:uri.query})){exec(value);}",
        "const value=flag?{command:'fixed'}:JSON.parse(uri.query); exec(value.command);",
        "const value=flag?['fixed']:JSON.parse(uri.query); exec(value[0]);",
        "const id='fixed'; const records=flag?{[id]:'fixed'}:JSON.parse(uri.query); for(const [,value] of Object.entries(records)){exec(value);}",
        "const id='fixed'; const records=flag?{[id]:{command:'fixed'}}:JSON.parse(uri.query); for(const [,value] of Object.entries(records)){exec(value.command);}",
        "class Box{constructor(public command:string){}} const box=new Box(uri.query); for(const [,value] of Object.entries(box)){exec(value);}",
        "for(const [,value] of Object.entries({fixed:uri.query})){exec(value);}",
        "for(const [,value] of Object.entries({fixed:{command:uri.query}})){exec(value.command);}",
        "for(const [key] of Object.entries({[uri.query]:'fixed'})){exec(key);}",
        "for(const [key] of Object.entries(JSON.parse(uri.query)||{})){exec(key);}",
        "for(const [,value] of Object.entries(JSON.parse(uri.query)||{})){exec(value);}",
        "const records={fixed:{command:'fixed'}}; const alias=records.fixed; alias.command=uri.query; for(const [,value] of Object.entries(records)){exec(value.command);}",
        "const Object={entries(value:any){return [[value,'fixed']];}}; for(const [key] of Object.entries(uri.query)){exec(key);}",
    ])("retains key and value inputs through %s", async (body) => {
        expect((await scan(body)).filter((finding) => finding.sink.name === "exec")).toHaveLength(1);
    });
});
