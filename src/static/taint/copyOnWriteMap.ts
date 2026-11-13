/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/** Values must be immutable; forks share entries until a map changes. */
export class CopyOnWriteMap<K, V> extends Map<K, V> {
    private backing: { entries: Map<K, V>; shared: boolean; identity: object };
    private iterators = 0;

    constructor(
        entries?: Iterable<readonly [K, V]>,
        private readonly ownValue: (value: V) => V = (value) => value,
    ) {
        super();
        this.backing = { entries: this.copyEntries(entries), shared: false, identity: {} };
    }

    private copyEntries(entries?: Iterable<readonly [K, V]>): Map<K, V> {
        const result = new Map<K, V>();
        if (entries) for (const [key, value] of entries) result.set(key, this.ownValue(value));
        return result;
    }

    get storageIdentity(): object {
        return this.backing.identity;
    }
    hasValueOwner(owner: (value: V) => V): boolean {
        return this.ownValue === owner;
    }
    get size(): number {
        return this.backing.entries.size;
    }
    get(key: K): V | undefined {
        return this.backing.entries.get(key);
    }
    has(key: K): boolean {
        return this.backing.entries.has(key);
    }

    fork(): CopyOnWriteMap<K, V> {
        const fork = new CopyOnWriteMap<K, V>(undefined, this.ownValue);
        // Active native iterators must keep seeing writes to their original map.
        if (this.iterators > 0) {
            fork.backing = {
                entries: this.copyEntries(this.backing.entries),
                shared: false,
                identity: this.backing.identity,
            };
        } else {
            this.backing.shared = true;
            fork.backing = this.backing;
        }
        return fork;
    }

    replaceWith(source: CopyOnWriteMap<K, V>): void {
        if (source === this) return;
        if (this.iterators > 0 || this.ownValue !== source.ownValue) {
            this.clear();
            for (const [key, value] of source) this.set(key, value);
        } else {
            this.backing = source.fork().backing;
        }
    }

    private own(): void {
        if (this.backing.shared) {
            this.backing = {
                entries: this.copyEntries(this.backing.entries),
                shared: false,
                identity: this.backing.identity,
            };
        }
    }

    set(key: K, value: V): this {
        const owned = this.ownValue(value);
        if (this.has(key) && Object.is(this.get(key), owned)) return this;
        this.own();
        this.backing.entries.set(key, owned);
        this.backing.identity = {};
        return this;
    }

    delete(key: K): boolean {
        if (!this.has(key)) return false;
        this.own();
        this.backing.identity = {};
        return this.backing.entries.delete(key);
    }

    clear(): void {
        if (this.size === 0) return;
        if (this.backing.shared) this.backing = { entries: new Map(), shared: false, identity: {} };
        else {
            this.backing.entries.clear();
            this.backing.identity = {};
        }
    }

    private iterate<T>(factory: (entries: Map<K, V>) => MapIterator<T>): MapIterator<T> {
        // Iteration owns its map so mutation remains live without changing a fork.
        this.own();
        const iterator = factory(this.backing.entries);
        this.iterators++;
        let active = true;
        const release = () => {
            if (active) {
                active = false;
                this.iterators--;
            }
        };
        return {
            next: () => {
                if (!active) return { done: true, value: undefined };
                const result = iterator.next();
                if (result.done) release();
                return result;
            },
            return: () => {
                release();
                return { done: true, value: undefined };
            },
            [Symbol.iterator]() {
                return this;
            },
        } as MapIterator<T>;
    }

    entries(): MapIterator<[K, V]> {
        return this.iterate((entries) => entries.entries());
    }
    keys(): MapIterator<K> {
        return this.iterate((entries) => entries.keys());
    }
    values(): MapIterator<V> {
        return this.iterate((entries) => entries.values());
    }
    [Symbol.iterator](): MapIterator<[K, V]> {
        return this.entries();
    }
    forEach(callback: (value: V, key: K, map: Map<K, V>) => void, thisArg?: unknown): void {
        if (typeof callback !== "function") throw new TypeError("Callback must be a function");
        for (const [key, value] of this) callback.call(thisArg, value, key, this);
    }
}
