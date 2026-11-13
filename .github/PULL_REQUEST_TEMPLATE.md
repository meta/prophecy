## Summary

Describe the problem and how this change fixes it. Link any related issues.
For analyzer changes, explain which source-to-sink flows should change and why.

## Test plan

List the exact commands you ran and their results. Add regression tests for
changed behavior, including a safe control where applicable.

```bash
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm test --runInBand
pnpm test:pnpm
```

<!-- Replace the example commands above with the commands actually run.
Note any checks you could not run and why. -->

## Checklist

- [ ] Added or updated tests for changed behavior, or explained why none are needed.
- [ ] Updated documentation if usage or supported behavior changed.
- [ ] Ran `pnpm lint` and `pnpm format:check`.
- [ ] Kept examples and logs free of credentials and private source code.
