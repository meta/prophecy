import { exec, execFile } from "child_process";

export function unsafeCommand(input: string): void {
    const { path } = JSON.parse(input);
    exec(["formatter", "--write", path].join(" "));
}

export function safeCommand(input: string): void {
    const { path } = JSON.parse(input);
    execFile("formatter", ["--write", path], { shell: false });
}
