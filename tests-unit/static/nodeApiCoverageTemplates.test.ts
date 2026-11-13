/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { analyze } from "../../src/static/analyzer";
import { expressSpec } from "../../src/static/spec/express";

// res.render(view, locals?, callback?): the view selects a file and may select
// its engine. Locals values are data, not template source. Whether particular
// keys or unescaped interpolation are unsafe requires a view-engine model.
// https://expressjs.com/en/5x/api/response/#resrender

async function scan(statements: string) {
    const result = await analyze({
        source: `import express from 'express'; const app = express();
            app.get('/', (req, response) => { ${statements} });`,
        spec: expressSpec,
        outputFormat: "json",
    });
    expect(result.syntaxErrors).toEqual([]);
    expect(result.skippedEntryPoints).toEqual([]);
    return result.findings;
}

describe("nodeApiCoverage template selection versus locals", () => {
    it("reports attacker-controlled view selection, not blanket SSTI", async () => {
        const findings = await scan(`response.render(req.query.view, {title: 'fixed'});`);
        expect(findings.map((f) => [f.sink.name, f.sink.categories])).toEqual([["render", ["lfi"]]]);
    });

    it("does not classify ordinary locals as template code or proven unescaped HTML", async () => {
        expect(
            await scan(`
            response.render('page', {title: req.query.title});
            response.render('page', {nested: {value: req.body}});
        `),
        ).toEqual([]);
    });

    it("keeps selection taint through helper arguments and callback overloads", async () => {
        const findings = await scan(`
            function render(output: any, view: any) { output.render(view, () => {}); }
            render(response, req.query.view);
        `);
        expect(findings.map((f) => f.sink.categories)).toEqual([["lfi"]]);
    });

    it("does not match unrelated local render methods", async () => {
        expect(
            await scan(`
            const renderer = {render(value: any, locals?: any) {}};
            renderer.render(req.query.view, req.body);
        `),
        ).toEqual([]);
    });
});
