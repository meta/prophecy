/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Test fixture: filenames as a taint source.
//
// Modeled on an extension that lists a project's Ruby library files and passes
// their paths to ruby with {shell: true}. On POSIX, Node joins argv into a
// /bin/sh -c string, so shell syntax in a filename is evaluated. This fixture
// reads the directory on activation, not on file-open/save events.
//
// A filename is attacker-controlled wherever an attacker can add a file, such
// as a repository, a cloned checkout, or an unpacked archive.
import * as vscode from "vscode";
import * as child_process from "child_process";

export async function activate(context: vscode.ExtensionContext) {
    const libraries = vscode.Uri.file("/repo/lib");
    const files = await vscode.workspace.fs.readDirectory(libraries);

    const paths = files.map(f => vscode.Uri.joinPath(libraries, f[0]).fsPath);

    // VULN: shell:true joins argv unquoted into /bin/sh -c.
    const cmd = ["/usr/bin/ruby", "-", "--"].concat(paths);
    child_process.spawn(cmd.shift() || "", cmd, {shell: true});
}
