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
            export function activate() {
                vscode.window.registerUriHandler({handleUri(uri: vscode.Uri) { ${body} }});
            }`,
        fileName: "/src/argument-binding.ts",
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("Function argument binding", () => {
    it.each([
        "function run({command}: {command: string}) {exec(command)}; run({command: uri.query});",
        "function run({value: {command}}: {value: {command: string}}) {exec(command)}; run({value: {command: uri.query}});",
        "function run([command]: [string]) {exec(command)}; run([uri.query]);",
        "function run({command} = {command: uri.query}) {exec(command)}; run();",
        "class Run { constructor({command}: {command: string}) {exec(command)} }; new Run({command: uri.query});",
        "class Run { call({command}: {command: string}) {exec(command)} }; new Run().call({command: uri.query});",
        'function run(...commands: string[]) {exec(commands[1])}; run("safe", uri.query);',
        'function run(mode: string, command: string) {exec(command)}; run(...["safe", uri.query] as [string, string]);',
        'function run(mode: string, command: string) {exec(command)}; const args = ["safe", uri.query] as [string, string]; run(...args);',
        'function run(mode: string, command = uri.query) {exec(command)}; run(...["safe", undefined] as [string, undefined]);',
        'class Run { constructor(...commands: string[]) {exec(commands[1])} }; new Run("safe", uri.query);',
        'class Run { constructor(mode: string, command: string) {exec(command)} }; new Run(...["safe", uri.query] as [string, string]);',
        'vscode.commands.registerCommand("demo.run", ({command}) => exec(command)); vscode.commands.executeCommand("demo.run", {command: uri.query});',
        'vscode.commands.registerCommand("demo.run", (...commands) => exec(commands[1])); vscode.commands.executeCommand("demo.run", "safe", uri.query);',
    ])("preserves attacker input through %s", async (body) => {
        expect(await scan(body)).toHaveLength(1);
    });

    it.each([
        'function run({command}: {command: string; unused: string}) {exec(command)}; run({command: "safe", unused: uri.query});',
        "function run({command}: {command: number}) {exec(`${command}`)}; run({command: Number(uri.query)});",
        'function run(command: string, unused: string) {exec(command)}; run(...["safe", uri.query] as [string, string]);',
        'function run({command} = {command: uri.query}) {exec(command)}; run({command: "safe"});',
    ])("keeps clean selected values clean through %s", async (body) => {
        expect(await scan(body)).toHaveLength(0);
    });

    it.each([
        "function run({runner}: {runner: Runner}) {exec(runner.command)}; run({runner: new Runner(uri.query)});",
        "function run([runner]: [Runner]) {exec(runner.command)}; run([new Runner(uri.query)]);",
        'function run(...runners: Runner[]) {exec(runners[1].command)}; run(new Runner("safe"), new Runner(uri.query));',
        'function run(unused: Runner, runner: Runner) {exec(runner.command)}; run(...[new Runner("safe"), new Runner(uri.query)] as [Runner, Runner]);',
    ])("preserves contained instance state through %s", async (body) => {
        expect(await scan(`class Runner { constructor(public command: string) {} } ${body}`)).toHaveLength(1);
    });

    it("merges unknown spread instances into wildcard rest elements", async () => {
        expect(
            await scan(`
            class Runner { constructor(public command: string) {} }
            function run(head: Runner, ...rest: Runner[]) { exec(rest[0].command); }
            const runners = [new Runner("safe"), new Runner(uri.query)];
            run(...runners);
        `),
        ).toHaveLength(1);
    });

    it("keeps known prefix instances out of an uncertain rest parameter", async () => {
        expect(
            await scan(`
            class Runner { constructor(public command: string) {} }
            function run(head: Runner, ...rest: Runner[]) { exec(rest[0].command); }
            const runners = [new Runner("safe")];
            run(new Runner(uri.query), ...runners);
        `),
        ).toHaveLength(0);
    });

    it("seeds destructured source parameters", async () => {
        const result = await analyze({
            source: `import * as vscode from "vscode"; import {exec} from "child_process";
                export function activate() {
                    vscode.window.registerUriHandler({handleUri({query}: vscode.Uri) {exec(query)}});
                }`,
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(1);
    });

    it("seeds destructured callback parameters at the call site", async () => {
        const result = await analyze({
            source: `import {readFile} from "fs"; import {exec} from "child_process";
                export function activate() {
                    readFile("config.txt", "utf8", (error, [command]) => exec(command));
                }`,
            outputFormat: "json",
        });
        expect(result.findings).toHaveLength(1);
    });
});
