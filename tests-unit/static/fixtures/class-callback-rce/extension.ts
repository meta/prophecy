import { exec } from "child_process";
import { Hook as FrameworkHook, Input } from "./framework";
import { safeCommand, unsafeCommand } from "./command";

abstract class Intermediate extends FrameworkHook {}

export class UnsafeHook extends Intermediate {
    protected run(input: Input): void {
        unsafeCommand(input.payload);
    }
}

export class SafeHook extends FrameworkHook {
    protected run = (input: Input): void => {
        safeCommand(input.payload);
    };
}

export class MetadataHook extends FrameworkHook {
    protected run(input: Input): void {
        exec(input.metadata);
    }
}

export class StaticHook extends FrameworkHook {
    static run(input: Input): void {
        exec(input.payload);
    }
    protected run(_input: Input): void {}
}

export function activate(): void {}
