/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The extension constructs this subclass under the library's name, so only its
// `super(...)` call reaches the vscode-languageclient constructor.
import {
    LanguageClient as VscodeLanguageClient,
    LanguageClientOptions,
    ServerOptions,
} from "vscode-languageclient/node";

export default class LanguageClientEx extends VscodeLanguageClient {
    constructor(
        id: string,
        name: string,
        serverOptions: ServerOptions,
        clientOptions: LanguageClientOptions,
        forceDebug?: boolean,
    ) {
        super(id, name, serverOptions, clientOptions, forceDebug);
    }
}
