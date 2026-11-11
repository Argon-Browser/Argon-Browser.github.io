// SPDX-License-Identifier: MPL-2.0

/**
 * JSON-safety gate for untrusted manifest data.
 *
 * A real manifest.json reaches this module through JSON.parse, which can never
 * produce accessors, exotic prototypes, or cycles. The gate exists for the case
 * where a manifest object arrives from another code path: it must be treated as
 * hostile input that can execute code.
 *
 * Two rules make that safe:
 *
 *   1. Values are read through property descriptors, never through
 *      `value[key]`, so an accessor or a Proxy `get` trap is never invoked.
 *   2. The result is rebuilt into a fresh plain object with defineProperty, so
 *      a key such as `__proto__` is copied as data and can never reach a
 *      prototype.
 *
 * Enumerating keys necessarily goes through the `ownKeys` proxy trap, and a
 * handler that forwards every trap is semantically identical to its target, so
 * a Proxy cannot be recognized. What this module guarantees is that no
 * extension-controlled code runs and that the analysis sees only JSON data.
 */

const MAX_DEPTH = 32;
const MAX_ARRAY_LENGTH = 4096;
const OBJECT_TAG = '[object Object]';
const ARRAY_TAG = '[object Array]';

const tagOf = (value) => Object.prototype.toString.call(value);

/**
 * Convert a value into a JSON-only copy.
 *
 * @returns {{ok: true, value: *}|{ok: false, message: string}}
 */
function convert(value, depth, ancestors) {
  if (depth > MAX_DEPTH) {
    return { ok: false, message: `Manifest data nested deeper than ${MAX_DEPTH} levels is rejected.` };
  }
  if (value === null) return { ok: true, value: null };

  const type = typeof value;
  if (type === 'string' || type === 'boolean') return { ok: true, value };
  if (type === 'number') {
    return Number.isFinite(value)
      ? { ok: true, value }
      : { ok: false, message: 'NaN and Infinity are not JSON values.' };
  }
  if (type !== 'object') {
    return { ok: false, message: `${type} values are not JSON data.` };
  }
  if (ancestors.has(value)) {
    return { ok: false, message: 'Circular references are not JSON data.' };
  }

  const kind = tagOf(value);
  if (kind === ARRAY_TAG) {
    if (value.length > MAX_ARRAY_LENGTH) {
      return { ok: false, message: `Arrays longer than ${MAX_ARRAY_LENGTH} entries are rejected.` };
    }
    ancestors.add(value);
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      // A missing descriptor is an array hole, which JSON cannot represent.
      const descriptor = Object.getOwnPropertyDescriptor(value, index);
      if (!descriptor) {
        return { ok: false, message: 'Array holes are not JSON data.' };
      }
      if (descriptor.get || descriptor.set) {
        return { ok: false, message: 'Accessor properties are not JSON data.' };
      }
      const converted = convert(descriptor.value, depth + 1, ancestors);
      if (!converted.ok) return converted;
      copy.push(converted.value);
    }
    ancestors.delete(value);
    return { ok: true, value: copy };
  }

  if (kind !== OBJECT_TAG) {
    return { ok: false, message: `${kind.slice(8, -1)} instances are not JSON data.` };
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return { ok: false, message: 'Only plain objects are JSON data.' };
  }

  ancestors.add(value);
  const copy = {};
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor.get || descriptor.set) {
      return { ok: false, message: 'Accessor properties are not JSON data.' };
    }
    const converted = convert(descriptor.value, depth + 1, ancestors);
    if (!converted.ok) return converted;
    // defineProperty keeps a key such as __proto__ an own data property.
    Object.defineProperty(copy, key, {
      value: converted.value, enumerable: true, writable: true, configurable: true,
    });
  }
  ancestors.delete(value);
  return { ok: true, value: copy };
}

/**
 * @returns {{ok: true, manifest: object}|{ok: false, message: string}}
 */
export function sanitizeManifest(manifest) {
  const result = convert(manifest, 1, new Set());
  return result.ok
    ? { ok: true, manifest: result.value }
    : { ok: false, message: result.message };
}
