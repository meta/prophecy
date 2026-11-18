/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Standalone integration test, not a Jest test: installs only its fixture.
// Usage after building Prophecy: node tests/pnpm-extension.test.js
// pnpm must be on PATH (the canonical wrapper in internal CI).
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const CLI = path.join(ROOT, "dist/index.js");
const FIXTURE = path.join(ROOT, "tests-unit/static/fixtures/pnpm-extension");

function run(command, args, cwd, timeout = 30_000) {
    const env = { ...process.env, NO_COLOR: "1" };
    delete env.FORCE_COLOR;
    const result = spawnSync(command, args, {
        cwd,
        encoding: "utf8",
        timeout,
        maxBuffer: 4 * 1024 * 1024,
        env,
    });
    const details = `${command} ${args.join(" ")}\n${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    assert.ifError(result.error);
    assert.equal(result.signal, null, details);
    assert.notEqual(result.status, null, details);
    return { ...result, details };
}

function succeed(command, args, cwd, timeout) {
    const result = run(command, args, cwd, timeout);
    assert.equal(result.status, 0, result.details);
    return result;
}

function localPackage(name, version) {
    const link = path.join(FIXTURE, "node_modules", name);
    assert.ok(fs.lstatSync(link).isSymbolicLink(), `${name} must be a direct pnpm link`);
    const resolved = fs.realpathSync(link);
    const store = path.join(fs.realpathSync(FIXTURE), "node_modules/.pnpm");
    assert.equal(fs.realpathSync(store), store, "Fixture virtual store must not link to an ancestor store");
    const relative = path.relative(store, resolved);
    assert.ok(
        relative && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative),
        `${name} escaped fixture node_modules/.pnpm: ${resolved}`,
    );
    assert.equal(JSON.parse(fs.readFileSync(path.join(resolved, "package.json"), "utf8")).version, version);
    console.log(`PASS: ${name}@${version} -> node_modules/.pnpm/${relative.split(path.sep).join("/")}`);
    return resolved;
}

function scan(project) {
    return run(
        process.execPath,
        [CLI, "--project", project, "--rules", "auto", "--require-types", "--format", "json"],
        project,
    );
}

function findings(project) {
    const result = scan(project);
    assert.equal(result.status, 0, result.details);
    assert.doesNotMatch(result.stderr, /Missing type declarations|entry point\(s\) incomplete|UNEXPECTED error/);
    const output = JSON.parse(result.stdout);
    assert.ok(Array.isArray(output), result.details);
    return output;
}

// Only declarations explicitly linked into each disposable project are visible
// through typeRoots. Never unlink installed packages or rely on ancestor hoisting.
function copyProject(directory, source, declarations) {
    fs.mkdirSync(path.join(directory, "node_modules/@types"), { recursive: true });
    for (const file of ["package.json", "tsconfig.json"]) {
        fs.copyFileSync(path.join(FIXTURE, file), path.join(directory, file));
    }
    fs.copyFileSync(path.join(FIXTURE, source), path.join(directory, "extension.ts"));
    for (const [name, target] of Object.entries(declarations)) {
        fs.symlinkSync(target, path.join(directory, "node_modules/@types", name), "junction");
    }
}

function main() {
    assert.ok(fs.existsSync(CLI), "Build Prophecy first (pnpm build); this runner does not build root dist");
    const lockPath = path.join(FIXTURE, "pnpm-lock.yaml");
    const lock = fs.readFileSync(lockPath, "utf8");
    // A clean install prevents stale fixture packages from satisfying the test.
    fs.rmSync(path.join(FIXTURE, "node_modules"), { recursive: true, force: true });
    fs.rmSync(path.join(FIXTURE, "dist"), { recursive: true, force: true });
    const install = succeed("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts"], FIXTURE, 120_000);
    assert.equal(fs.readFileSync(lockPath, "utf8"), lock, "Frozen install must not modify the committed lockfile");
    console.log(install.stdout.trim());
    console.log("PASS: pnpm install --frozen-lockfile --ignore-scripts");

    const declarations = {
        node: localPackage("@types/node", "20.19.33"),
        vscode: localPackage("@types/vscode", "1.109.0"),
    };
    const compiler = path.join(localPackage("typescript", "5.9.3"), "bin/tsc");
    succeed("pnpm", ["run", "build"], FIXTURE);
    assert.ok(fs.existsSync(path.join(FIXTURE, "dist/extension.js")), "Fixture extension was not emitted");
    console.log("PASS: pnpm run build emitted dist/extension.js");

    const output = findings(FIXTURE);
    assert.equal(output.length, 1, JSON.stringify(output, null, 2));
    const finding = output[0];
    assert.equal(finding.source.pattern, "handleUri.uri");
    assert.equal(finding.sink.pattern, "child_process.exec");
    assert.equal(finding.sink.name, "exec");
    assert.deepEqual(finding.sink.categories, ["rce"]);
    assert.equal(path.resolve(finding.sourceLocation.fileName), path.join(FIXTURE, "extension.ts"));
    assert.equal(finding.sourceLocation.line, 14);
    assert.equal(path.resolve(finding.sinkLocation.fileName), path.join(FIXTURE, "extension.ts"));
    assert.equal(finding.sinkLocation.line, 15);
    assert.equal(finding.sinkLocation.text, "exec(uri.query)");
    console.log(
        "PASS: auto preset + --require-types reports exactly handleUri.uri -> child_process.exec at extension.ts:15",
    );

    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "prophecy-pnpm-extension-"));
    try {
        const safe = path.join(temporary, "safe");
        copyProject(safe, "safe.ts", declarations);
        succeed(process.execPath, [compiler, "--project", path.join(safe, "tsconfig.json")], safe);
        assert.deepEqual(findings(safe), []);
        console.log("PASS: safe URI handler with a constant shell command has zero findings");

        for (const missing of ["node", "vscode"]) {
            const project = path.join(temporary, `missing-${missing}`);
            const present = { ...declarations };
            delete present[missing];
            copyProject(project, "extension.ts", present);
            const build = run(process.execPath, [compiler, "--project", path.join(project, "tsconfig.json")], project);
            assert.notEqual(build.status, 0, build.details);
            assert.ok(
                build.stdout.includes(`TS2688: Cannot find type definition file for '${missing}'`),
                build.details,
            );
            assert.ok(
                !fs.existsSync(path.join(project, "dist/extension.js")),
                "Missing declarations must prevent emit",
            );
            const analysis = scan(project);
            assert.notEqual(analysis.status, 0, analysis.details);
            assert.match(analysis.stderr, /Missing type declarations/);
            assert.ok(analysis.stderr.includes(`were not found (${missing})`), analysis.details);
            assert.equal(analysis.stdout.trim(), "", analysis.details);
            console.log(`PASS: missing @types/${missing} fails both tsc (TS2688) and Prophecy --require-types`);
        }
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
    console.log("PASS: pnpm-installed VS Code extension regression");
}

try {
    main();
} catch (error) {
    console.error(`FAIL: pnpm-installed VS Code extension regression\n${error.stack ?? error}`);
    process.exitCode = 1;
}
