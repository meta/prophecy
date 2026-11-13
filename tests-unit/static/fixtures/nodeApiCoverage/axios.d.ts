/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Minimal declaration surface from Axios 1.13.1 index.d.ts, preserving the
// actual default-instance, request and payload/config overload contracts.
// No implementation is supplied: analysis must use the imported API identity.
declare module "axios" {
    export interface AxiosRequestConfig<D = any> {
        url?: string;
        baseURL?: string;
        data?: D;
        headers?: Record<string, unknown>;
        params?: any;
    }
    export interface AxiosResponse<T = any> { data: T; }
    export class Axios {
        request<T = any, R = AxiosResponse<T>, D = any>(config: AxiosRequestConfig<D>): Promise<R>;
        get<T = any, R = AxiosResponse<T>, D = any>(url: string, config?: AxiosRequestConfig<D>): Promise<R>;
        post<T = any, R = AxiosResponse<T>, D = any>(url: string, data?: D, config?: AxiosRequestConfig<D>): Promise<R>;
    }
    export interface AxiosInstance extends Axios {
        create(config?: AxiosRequestConfig): AxiosInstance;
        <T = any, R = AxiosResponse<T>, D = any>(config: AxiosRequestConfig<D>): Promise<R>;
        <T = any, R = AxiosResponse<T>, D = any>(url: string, config?: AxiosRequestConfig<D>): Promise<R>;
    }
    export interface AxiosStatic extends AxiosInstance {}
    const axios: AxiosStatic;
    export default axios;
}
