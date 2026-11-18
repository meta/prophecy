import { exec } from "child_process";
import type { Input } from "./framework";

abstract class Hook {
    protected abstract run(input: Input): void;
}

export class LocalHook extends Hook {
    protected run(input: Input): void {
        exec(input.payload);
    }
}
