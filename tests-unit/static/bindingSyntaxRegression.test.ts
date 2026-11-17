/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";

async function scan(body: string) {
    const result = await analyze({
        source: `import * as vscode from "vscode"; import {exec} from "child_process";
            declare function mutate(box: unknown): void;
            export function activate() {
                vscode.window.registerUriHandler({async handleUri(uri: vscode.Uri) { ${body} }});
            }`,
        fileName: "/src/binding-syntax.ts",
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings.filter((finding) => finding.sink.name === "exec");
}

describe("Binding syntax and operand effects", () => {
    it.each([
        ["nested object", "const {nested:{command}}={nested:{command:uri.query}}; exec(command);"],
        ["nested array", "const [[command]]=[[uri.query]]; exec(command);"],
        ["object default", "const {command=uri.query}={}; exec(command);"],
        ["undefined object default", "const {command=uri.query}={command:undefined}; exec(command);"],
        ["array default", "const [command=uri.query]=[]; exec(command);"],
        ["array hole default", "const [command=uri.query]=[,]; exec(command);"],
        ["nested default", "const {nested:{command=uri.query}={}}={}; exec(command);"],
        ["parameter default", "function run({command=uri.query}){exec(command)} run({});"],
        ["array parameter default", "function run([command=uri.query]){exec(command)} run([]);"],
        ["rest property", "const {safe,...rest}={safe:'fixed',command:uri.query}; exec(rest.command);"],
        ["array rest", "const [safe,...rest]=['fixed',uri.query]; exec(rest[0]);"],
        ["nested rest", "const {nested,...rest}={nested:{safe:'fixed'},command:uri.query}; exec(rest.command);"],
        ["assignment object", "let command='fixed'; ({nested:{command}}={nested:{command:uri.query}}); exec(command);"],
        ["assignment array", "let command='fixed'; [[command]]=[[uri.query]]; exec(command);"],
        ["assignment default", "let command='fixed'; ({command=uri.query}={}); exec(command);"],
        ["existing loop target", "let command='fixed'; for(command of [uri.query]){exec(command)}"],
        ["loop object binding", "for(const {command} of [{command:uri.query}]){exec(command)}"],
        ["loop nested binding", "for(const {nested:{command}} of [{nested:{command:uri.query}}]){exec(command)}"],
        ["loop assignment binding", "let command='fixed'; for({command} of [{command:uri.query}]){exec(command)}"],
        ["loop field target", "const box={command:'fixed'}; for(box.command of [uri.query]){exec(box.command)}"],
        ["typeof call", "typeof exec(uri.query);"],
        ["delete key call", "const values={}; delete values[exec(uri.query) as any];"],
        ["delete call", "delete (exec(uri.query) as any);"],
        [
            "default after deletion",
            "const box={command:'fixed'}; delete box.command; const {command=uri.query}=box; exec(command);",
        ],
        [
            "default after overwrite",
            "const box={command:'fixed' as string|undefined}; box.command=undefined; const {command=uri.query}=box; exec(command);",
        ],
        [
            "unknown supplied value",
            "let supplied:any=undefined; const {command=uri.query}={command:supplied}; exec(command);",
        ],
        [
            "conditional missing property",
            "const box=uri.query?{command:'fixed'}:{}; const {command=uri.query}=box; exec(command);",
        ],
        [
            "conditional overwrite",
            "const box={command:'fixed' as string|undefined}; if(uri.query)box.command=undefined; const {command=uri.query}=box; exec(command);",
        ],
        ["opaque mutation", "const box={command:'fixed'}; mutate(box); const {command=uri.query}=box; exec(command);"],
        [
            "mutable source",
            "let supplied:any='fixed'; supplied=undefined; const {command=uri.query}={command:supplied}; exec(command);",
        ],
    ])("preserves input through %s", async (_name, body) => {
        expect(await scan(body)).toHaveLength(1);
    });

    it.each([
        ["nested clean sibling", "const {nested:{safe}}={nested:{safe:'fixed',command:uri.query}}; exec(safe);"],
        ["nested clean array", "const [[command]]=[['fixed'],[uri.query]]; exec(command);"],
        ["provided object value", "const {command=uri.query}={command:'fixed'}; exec(command);"],
        ["provided array value", "const [command=uri.query]=['fixed']; exec(command);"],
        ["provided null", "const {command=uri.query}={command:null}; exec(String(command));"],
        ["provided nested value", "const {nested:{command=uri.query}={}}={nested:{command:'fixed'}}; exec(command);"],
        ["provided parameter value", "function run({command=uri.query}){exec(command)} run({command:'fixed'});"],
        ["provided array parameter", "function run([command=uri.query]){exec(command)} run(['fixed']);"],
        ["excluded rest property", "const {command,...rest}={command:uri.query,safe:'fixed'}; exec(rest.safe);"],
        ["excluded array prefix", "const [command,...rest]=[uri.query,'fixed']; exec(rest[0]);"],
        ["rebased array rest", "const [safe,...rest]=['fixed','also-fixed',uri.query]; exec(rest[0]);"],
        ["loop clean sibling", "for(const {safe} of [{safe:'fixed',command:uri.query}]){exec(safe)}"],
        ["loop clean target", "let command=uri.query; for(command of ['fixed']){exec(command)}"],
        ["unused default effects", "const {command=exec(uri.query)}={command:'fixed'};"],
        ["unused array default effects", "const [command=exec(uri.query)]=['fixed'];"],
        ["unconditional default effects", "let command=uri.query; const {value=(command='fixed')}={}; exec(command);"],
        ["object clear", "const box={command:uri.query}; box.command='fixed'; exec(box.command);"],
        ["deleted object property", "const box={command:uri.query}; delete box.command; exec(box.command);"],
        ["deleted array element", "const values=[uri.query]; delete values[0]; exec(values[0]);"],
        ["typeof result", "const value=typeof uri.query; exec(value);"],
        ["delete result", "const box={command:uri.query}; exec(String(delete box.command));"],
    ])("keeps %s clean", async (_name, body) => {
        expect(await scan(body)).toHaveLength(0);
    });

    it.each([
        "const {nested:{runner}}={nested:{runner:new Runner(uri.query)}}; exec(runner.command);",
        "const [[runner]]=[[new Runner(uri.query)]]; exec(runner.command);",
        "const {safe,...rest}={safe:'fixed',runner:new Runner(uri.query)}; exec(rest.runner.command);",
        "const [safe,...rest]=['fixed',new Runner(uri.query)]; exec(rest[0].command);",
        "for(const {runner} of [{runner:new Runner(uri.query)}]){exec(runner.command)}",
    ])("retains nested instance aliases through %s", async (body) => {
        expect(await scan(`class Runner {constructor(public command:string){}} ${body}`)).toHaveLength(1);
    });
});
