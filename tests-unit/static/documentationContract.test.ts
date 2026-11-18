/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as fs from "fs";
import * as path from "path";
import { analyze } from "../../src/static/analyzer";
import { formatFindings } from "../../src/static/reporter";
import { generateSappMetadata } from "../../src/static/sappFormatter";
import { validateSpec } from "../../src/static/spec/validate";

const root = path.resolve(__dirname, "../..");
const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
const documents = [
    "README.md",
    "SECURITY.md",
    "docs/architecture.md",
    "docs/development.md",
    "docs/framework-models.md",
    "docs/reading-reports.md",
    "docs/sapp.md",
    ".github/ISSUE_TEMPLATE.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
];

// The mirror supplies these shared documents outside the project's source directory.
const sharedDocuments = new Set(["CONTRIBUTING.md", "CODE_OF_CONDUCT.md"]);

describe("public documentation contracts", () => {
    it("keeps relative links inside the public export", () => {
        const broken: string[] = [];
        for (const document of documents) {
            const text = fs.readFileSync(path.join(root, document), "utf8");
            const links = text.matchAll(/\]\(([^)\s]+)\)|(?:src|href)="([^"]+)"/g);
            for (const match of links) {
                const link = match[1] ?? match[2];
                if (/^[a-z][a-z\d+.-]*:/i.test(link) || link.startsWith("#")) continue;
                const target = path.resolve(root, path.dirname(document), link.split("#")[0]);
                const relative = path.relative(root, target);
                const parts = relative.split(path.sep);
                const excluded = parts.some((part) =>
                    [
                        "..",
                        "facebook",
                        ".llms",
                        "skycastle",
                        "AGENTS.md",
                        "BUCK",
                        "PACKAGE",
                        "removeInternalFiles.sh",
                    ].includes(part),
                );
                if (excluded || (!sharedDocuments.has(relative) && !fs.existsSync(target))) {
                    broken.push(`${document}: ${link}`);
                }
            }
        }
        expect(broken).toEqual([]);
    });

    it("documents every emitted SAPP warning code and rule name", () => {
        const documented = [...readme.matchAll(/^\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|/gm)]
            .map((match) => `${match[1]}:${match[2]}`)
            .sort();
        const emitted = generateSappMetadata("documentation-test")
            .sapper.rules.map((rule) => `${rule.code}:${rule.name}`)
            .sort();
        expect(documented).toEqual(emitted);
    });

    it("shows the current bundled-fixture report", async () => {
        const result = await analyze({
            projectDir: path.join(root, "tests-unit/static/fixtures/uri-handler-rce"),
            outputFormat: "json",
            requireTypes: true,
        });
        expect(result.skippedEntryPoints).toEqual([]);
        expect(result.syntaxErrors).toEqual([]);
        expect(result.typeEnvironmentWarning).toBeUndefined();
        expect(result.entryPointCount).toBe(2);
        expect(result.findings).toHaveLength(1);
        // Public reports use file locations rather than repository-specific code-browser links.
        const report = formatFindings(result.findings).split(root).join("/path/to/prophecy").trim();
        expect(readme).toContain(report);
    });

    it("shows the custom spec fixture and the flow it reports", async () => {
        const section = readme.slice(readme.indexOf("## Custom specs"));
        const fixture = path.join(root, "tests-unit/static/fixtures/custom-spec");
        const spec = JSON.parse(fs.readFileSync(path.join(fixture, "spec.json"), "utf8"));
        expect(JSON.parse(/```json\n([\s\S]*?)\n```/.exec(section)?.[1] ?? "null")).toEqual(spec);
        // The formatter re-indents code blocks in Markdown.
        const dedent = (text: string) => text.replace(/^[ \t]+/gm, "");
        const handler = /```ts\n([\s\S]*?)\n```/.exec(section)?.[1] ?? "missing handler example";
        expect(dedent(fs.readFileSync(path.join(fixture, "main.ts"), "utf8"))).toContain(dedent(handler));
        expect(validateSpec(spec)).toEqual([]);
        const result = await analyze({ projectDir: fixture, spec, outputFormat: "json", requireTypes: true });
        expect(result.findings.map((finding) => finding.sinkLocation.text)).toEqual([
            "exec(`git checkout ${event.branch}`)",
        ]);
    });
});
