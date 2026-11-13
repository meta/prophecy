/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { exec } from "child_process";
import { promisify } from "util";

export const execAsync = promisify(exec);
