/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * Build-time metadata for Prophecy.
 *
 * Buck overwrites this source before compiling the packaged CLI so SAPP runner
 * metadata records the fbsource revision the tool was built from. Source-based
 * test runs keep this fallback value.
 */
export const PROPHECY_BUILD_REVISION = "unknown";
