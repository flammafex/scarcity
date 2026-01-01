/*
 * Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * core/crypto.ts
 * Centralized cryptographic utilities
 */

import * as crypto from "node:crypto";

/**
 * Generate a unique identifier
 *
 * Uses crypto.randomUUID() when available (Node.js 14.17+, modern browsers),
 * otherwise falls back to timestamp + random combination.
 *
 * @returns A unique identifier string
 */
export function generateId(): string {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Generate a shorter random ID suitable for peer identifiers
 *
 * @returns A short random string (7 characters)
 */
export function generatePeerId(): string {
  return `peer-${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Generate a random seed for deterministic operations
 *
 * @returns A random integer suitable for use as a PRNG seed
 */
export function generateSeed(): number {
  return Math.floor(Math.random() * 0xFFFFFFFF);
}
