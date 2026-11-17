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
            declare const flag: boolean;
            export function activate() {
                vscode.window.registerUriHandler({async handleUri(uri: vscode.Uri) { ${body} }});
            }`,
        fileName: "/src/exception-flow.ts",
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("Exception flow", () => {
    it.each([
        'let command=uri.query; try { JSON.parse("{}"); } catch { command="safe"; } exec(command);',
        'let command="safe"; try { command=uri.query; } catch { command="safe"; } exec(command);',
        'const box={command:uri.query}; try { JSON.parse("{}"); } catch { box.command="safe"; } exec(box.command);',
        'let command="safe"; try { if(flag) {command=uri.query; throw 0;} command="safe"; } catch {exec(command);}',
        'function fail(){throw 0;} let command="safe"; try { if(flag) {command=uri.query; fail();} command="safe"; } catch {exec(command);}',
        'let command="safe"; try { if(flag) {command=uri.query; await Promise.reject(0);} command="safe"; } catch {exec(command);}',
        'const box={command:"safe"}; try { if(flag) {box.command=uri.query; throw 0;} box.command="safe"; } catch {exec(box.command);}',
        "try {throw uri.query;} catch(command) {exec(command);}",
        'const box={command:"safe"}; try {throw box;} catch(e) {box.command=uri.query; exec(e.command);}',
        'function fail(v:any){throw v;} const box={command:"safe"}; try {fail(box);} catch(e) {box.command=uri.query; exec(e.command);}',
        'let command="safe"; try {command=uri.query; JSON.parse("bad"); command="safe";} catch {exec(command);}',
        'function parse(){JSON.parse("bad");} let command="safe"; try {command=uri.query; parse(); command="safe";} catch {exec(command);}',
        'let command="safe"; switch(1) {case 1: try {break;} finally {command=uri.query;}} exec(command);',
        'let command="safe"; for(let i=0;i<1;i++) {try {continue;} finally {command=uri.query;}} exec(command);',
        'function get(){const box={command:"safe"}; try {return box;} finally {try {throw {ignored:0};} catch {} box.command=uri.query;}} exec(get().command);',
        'function command(){try {return "safe";} finally {return uri.query;}} exec(command());',
        'function command(){try {return "safe";} finally {if(flag) return uri.query;}} exec(command());',
        'function command(){if(flag) return uri.query; try {return "safe";} finally {return "safe";}} exec(command());',
        'function get(){const box={command:"safe"}; try {return box;} finally {box.command=uri.query;}} exec(get().command);',
        'function get(){const box={command:"safe"}; try {return box;} finally {try {box.command=uri.query;} catch {}}} exec(get().command);',
        "try {try {throw uri.query;} catch(value) {throw value;}} catch(command) {exec(command);}",
    ])("retains reachable input through %s", async (body) => {
        expect(await scan(body)).toHaveLength(1);
    });

    it.each([
        'let command=uri.query; try {JSON.parse("{}");} catch {} finally {command="safe";} exec(command);',
        'function command(){try {return uri.query;} finally {return "safe";}} exec(command());',
        'function command(){try {throw uri.query;} finally {return "safe";}} exec(command());',
        'function command(){try {return uri.query;} finally {throw "safe";}} try {exec(command());} catch {}',
        'function get(){const box={command:uri.query}; try {return box;} finally {box.command="safe";}} exec(get().command);',
        "try {try {throw uri.query;} catch {} } catch(command) {exec(command);}",
        'function command(){try {return "safe";} finally {const discarded=()=>{throw uri.query;};}} exec(command());',
    ])("keeps superseded or caught input out of sinks through %s", async (body) => {
        expect(await scan(body)).toHaveLength(0);
    });
});
