/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The CommonJS build exports the loader directly. Use a typed require because
// this project's compiler configuration does not enable esModuleInterop.
import type { XXHashAPI } from "xxhash-wasm";
const xxhash: () => Promise<XXHashAPI> = require("xxhash-wasm");

import type { ObjectLiteralExpression } from "typescript";
import { SourceSpec, CodeLocation, SanitizerSpec, PropagationStep as FindingPropagationStep } from "../spec/types";
import { AnalysisMetrics } from "../metrics";

export interface PropagationChainNode {
    previous?: PropagationChainNode;
    step: PropagationStep;
    length: number;
}

/**
 * Represents a tainted value being tracked through the analysis.
 * Each TaintValue records which source introduced the taint and
 * a persistent chain of operations through which it propagated.
 */
export interface TaintValue {
    /** Which source introduced this taint. */
    source: SourceSpec;
    /** Where the source was in code. */
    sourceLocation: CodeLocation;
    /** Stable source portion used in interprocedural cache keys. */
    sourceCacheKey: string;
    /** Persistent chain tail. Materialize only when emitting a finding. */
    chain?: PropagationChainNode;
    /** Number of steps in the propagation chain. */
    chainLength: number;
    /** Stable hash of the propagation chain. */
    chainHash: string;
    /** Compact hash-based cache key; collisions are not checked. */
    cacheKey: string;
    /** Object-literal properties that must be selected before this taint is read. */
    aggregatePropertyPath?: readonly string[];
    /** Scoped sanitizers applied to this value. */
    sanitizers?: readonly AppliedSanitizer[];
    /** Location where this value became the program text for a nested shell. */
    nestedShellCommandLocation?: CodeLocation;
    /**
     * For a setting read, the key of the part of the setting this value is:
     * the key read, then each property read from its value.
     */
    settingPath?: readonly string[];
}

export interface AppliedSanitizer {
    spec: SanitizerSpec;
    /** Whether the sanitizer's required use-site context has been established. */
    contextSatisfied: boolean;
    /** Fixed command the value is a quoted argument of, once shell context is established. */
    shellCommand?: string;
}

export interface PropagationStep extends FindingPropagationStep {
    /** Literal container provenance used to distinguish executable argv operands. */
    arrayElement?: { containerId: string; index: number };
    /** Object literal holding the property an `objectProperty` step entered. */
    objectLiteral?: ObjectLiteralExpression;
    /** Container mutation represented by this step, when applicable. */
    mutationMethod?: string;
    /** Sanitizer applied by a `sanitizer` step. */
    sanitizer?: SanitizerSpec;
    /** The `sanitizer` step quoted each element, as `values.map(shlex.quote)` does. */
    elementWise?: true;
}

/**
 * Extends a taint value with a new propagation step.
 */
export function propagate(taint: TaintValue, step: PropagationStep, metrics?: AnalysisMetrics): TaintValue {
    const chain: PropagationChainNode = {
        previous: taint.chain,
        step,
        length: taint.chainLength + 1,
    };
    // Concatenate precomputed digests to avoid materializing the chain or
    // repeatedly encoding source paths on this per-propagation hot path.
    const chainHash = hashCacheInput(
        taint.chainHash +
            SEPARATOR +
            step.kind +
            SEPARATOR +
            locationDigest(step.location) +
            SEPARATOR +
            step.description,
    );
    recordTaintValue(metrics, chain.length, true);
    return {
        source: taint.source,
        sourceLocation: taint.sourceLocation,
        sourceCacheKey: taint.sourceCacheKey,
        chain,
        chainLength: chain.length,
        chainHash,
        cacheKey: buildCacheKey(taint.sourceCacheKey, chain.length, chainHash, taint.sanitizers),
        aggregatePropertyPath: taint.aggregatePropertyPath,
        sanitizers: taint.sanitizers,
        nestedShellCommandLocation: taint.nestedShellCommandLocation,
        settingPath: taint.settingPath,
    };
}

/**
 * Creates a new taint value from a source.
 */
export function createTaint(source: SourceSpec, sourceLocation: CodeLocation, metrics?: AnalysisMetrics): TaintValue {
    // Every propagated value retains the source key; store a digest rather
    // than repeating the source pattern and location in each key.
    const sourceCacheKey = hashCacheInput(source.pattern + SEPARATOR + locationDigest(sourceLocation));
    recordTaintValue(metrics, 0, false);
    return {
        source,
        sourceLocation,
        sourceCacheKey,
        chainLength: 0,
        chainHash: "0",
        cacheKey: buildCacheKey(sourceCacheKey, 0, "0"),
    };
}

export function withSanitizers(taint: TaintValue, sanitizers: readonly AppliedSanitizer[] | undefined): TaintValue {
    return {
        ...taint,
        sanitizers,
        cacheKey: buildCacheKey(taint.sourceCacheKey, taint.chainLength, taint.chainHash, sanitizers),
    };
}

export function materializePropagationChain(taint: TaintValue): PropagationStep[] {
    const chain = new Array<PropagationStep>(taint.chainLength);
    let node = taint.chain;
    for (let i = taint.chainLength - 1; i >= 0 && node; i--) {
        chain[i] = node.step;
        node = node.previous;
    }
    return chain;
}

function recordTaintValue(metrics: AnalysisMetrics | undefined, chainLength: number, isPropagation: boolean): void {
    if (!metrics) return;
    metrics.performance.taintValuesCreated++;
    if (isPropagation) {
        metrics.performance.taintPropagations++;
    }
    metrics.performance.maxPropagationChainLength = Math.max(
        metrics.performance.maxPropagationChainLength,
        chainLength,
    );
}

// Delimiter for hash inputs. Embedded NULs are not escaped, so this is not
// an injective encoding of arbitrary source text or spec data.
const SEPARATOR = "\0";

const sanitizerSpecDigests = new WeakMap<SanitizerSpec, string>();

function buildCacheKey(
    sourceCacheKey: string,
    chainLength: number,
    chainHash: string,
    sanitizers?: readonly AppliedSanitizer[],
): string {
    const base = `${sourceCacheKey}#${chainLength}:${chainHash}`;
    if (sanitizers == null || sanitizers.length === 0) return base;

    const state = sanitizers
        .map(({ spec, contextSatisfied, shellCommand }) => {
            let specDigest = sanitizerSpecDigests.get(spec);
            if (specDigest === undefined) {
                specDigest = hashCacheInput(
                    [
                        spec.kind,
                        spec.pattern,
                        spec.categories?.join(",") ?? "",
                        spec.sinkNames?.join(",") ?? "",
                        spec.requiresShellArgumentContext === true ? "1" : "0",
                        spec.numeric === true ? "1" : "0",
                        spec.shellCommandDenylist?.join(",") ?? "",
                    ].join(SEPARATOR),
                );
                sanitizerSpecDigests.set(spec, specDigest);
            }
            return `${specDigest}:${contextSatisfied ? "1" : "0"}:${shellCommand ?? ""}`;
        })
        .join(SEPARATOR);
    return `${base}:${hashCacheInput(state)}`;
}

/**
 * Cache location digests by object identity. `resolveNodeLocation` reuses
 * objects for AST nodes, avoiding repeated path encoding during propagation.
 * Location fields must not change after the first lookup.
 */
const locationDigests = new WeakMap<CodeLocation, string>();

function locationDigest(location: CodeLocation): string {
    let digest = locationDigests.get(location);
    if (digest === undefined) {
        digest = hashCacheInput(
            location.fileName +
                SEPARATOR +
                location.line +
                SEPARATOR +
                location.column +
                SEPARATOR +
                (location.text ?? ""),
        );
        locationDigests.set(location, digest);
    }
    return digest;
}

// xxhash64 keeps cache keys compact without retaining whole propagation chains.
// These non-cryptographic fingerprints are not collision-checked.
// Await initTaintValueHashing() before creating or propagating taint values.
let xxhashApi: XXHashAPI | undefined;

export async function initTaintValueHashing(): Promise<void> {
    if (!xxhashApi) {
        xxhashApi = await xxhash();
    }
}

function hashCacheInput(input: string): string {
    if (!xxhashApi) {
        throw new Error("initTaintValueHashing() must be awaited before any propagate() / hashCacheInput call");
    }
    // h64ToString returns the 16-char hex digest directly, skipping the
    // intermediate BigInt allocation that h64 would produce.
    return xxhashApi.h64ToString(input);
}
