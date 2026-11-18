export interface Input {
    payload: string;
    metadata: string;
}

export abstract class Hook {
    protected abstract run(input: Input): void;
}
