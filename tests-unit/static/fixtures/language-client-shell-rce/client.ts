/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import type { ServerOptions } from "vscode-languageclient/node";
import LanguageClient from "./languageClient";

export type DemoConfig = {
    lazyMode: string | null;
    stopOnExit: boolean;
};

type Options = {
    workspaceRoot: string;
    getConfig: () => DemoConfig;
};

export class DemoClient {
    private client: LanguageClient | null = null;

    constructor(private readonly options: Options) {
        this.init();
    }

    private async init(): Promise<void> {
        const config = this.options.getConfig();
        this.client = await this.createClient(config);
        this.client.start();
    }

    private async createClient(config: DemoConfig): Promise<LanguageClient> {
        const serverOptions: ServerOptions = {
            command: "demo",
            args: [
                "lsp",
                ...(config.lazyMode ? ["--lazy-mode", config.lazyMode] : []),
                config.stopOnExit ? "--autostop" : null,
            ].filter((v) => v != null),
            options: { shell: true },
        };
        return new LanguageClient("demo", "Demo", serverOptions, {
            documentSelector: [{ scheme: "file", language: "javascript" }],
            workspaceFolder: {
                name: "demo",
                index: 0,
                uri: this.options.workspaceRoot,
            },
        });
    }

    dispose(): void {
        this.client?.stop();
    }
}
