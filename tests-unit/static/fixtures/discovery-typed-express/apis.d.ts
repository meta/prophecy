/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
declare module "express" {
    export interface Request { query: Record<string, string>; body: Record<string, string>; }
    export interface Response { locals: Record<string, string>; send(value: string): void; }
    export type Handler = (request: Request, response: Response, next: () => void) => void;
    export interface Application {
        get(path: string, ...handlers: Handler[]): Application;
        post(path: string, ...handlers: Handler[]): Application;
        use(...handlers: Handler[]): Application;
    }
}
declare module "express-ws" {
    import {Application as ExpressApplication} from "express";
    export type Application = ExpressApplication & {ws(path: string, callback: unknown): void};
    export interface Instance {app: Application;}
}
