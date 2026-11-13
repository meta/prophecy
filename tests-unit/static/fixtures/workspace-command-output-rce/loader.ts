/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { exec } from "child_process";
import { promisify } from "util";
import * as vscode from "vscode";

const execAsync = promisify(exec);

interface TaskInfo {
    name: string;
    visible: boolean;
}

export class TaskLoader {
    private workingDir(): string {
        const folders = vscode.workspace.workspaceFolders;
        if (folders && folders.length > 0) {
            return folders[0].uri.fsPath;
        }
        return process.cwd();
    }

    async listTasks(): Promise<TaskInfo[]> {
        const { stdout } = await execAsync("taskctl --list-json", { cwd: this.workingDir(), timeout: 60000 });
        const raw = JSON.parse(stdout);
        return raw.map((task: any) => ({ ...task, name: task.name || task.id }));
    }

    async taskOptions(name: string): Promise<unknown> {
        const { stdout } = await execAsync(`taskctl --options-json ${name}`, { cwd: this.workingDir() });
        return JSON.parse(stdout);
    }

    async preload(): Promise<void> {
        const tasks = await this.listTasks();
        for (const task of tasks) {
            if (task.visible) await this.taskOptions(task.name);
        }
    }
}
