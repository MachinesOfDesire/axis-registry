/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * AXIS Protocol v0.2 §6.1 makes JCS the canonical encoding for every signed
 * canonical body in the protocol — registration proof, delegation envelope,
 * and action envelope. This replaces the v0.1 canonicalization
 * (`JSON.stringify(obj, Object.keys(obj).sort())`), which only sorted
 * TOP-LEVEL keys and silently stripped any nested key whose name didn't also
 * appear at the top level. That fragility is the proof-canonicalization hole
 * v0.2 closes.
 *
 * Why this implementation is correct for JSON-safe inputs:
 *
 *   - **Object key ordering.** RFC 8785 §3.2.3 sorts member keys by the UTF-16
 *     code units of the key strings. JavaScript's default `Array.prototype.sort`
 *     comparator on strings compares by UTF-16 code unit, which is exactly the
 *     ordering JCS mandates (including correct surrogate-pair behaviour). So
 *     `Object.keys(obj).sort()` is the right key order at every nesting level.
 *
 *   - **String serialization.** RFC 8785 §3.2.2.2 adopts the JSON string
 *     escaping of RFC 8259: escape only `"` `\` and the C0 control set (with
 *     the short escapes \b \f \n \r \t and \u00XX for the rest), never escape
 *     forward slash, never escape non-ASCII. `JSON.stringify` on a string
 *     produces exactly this. We therefore delegate string output to it.
 *
 *   - **Number serialization.** RFC 8785 §3.2.2.3 adopts the ECMAScript
 *     `Number.prototype.toString` algorithm. `JSON.stringify` on a number uses
 *     precisely that algorithm, so we delegate number output to it as well.
 *
 *   - **Whitespace.** JCS emits no insignificant whitespace. We build the
 *     output with no separators beyond the structural `,` and `:`.
 *
 * The only thing `JSON.stringify` does NOT do for us is recursively reorder
 * object keys (its array-replacer form filters keys but does not sort nested
 * objects, and it has no "sort all keys" mode), so that is the entire job of
 * the recursion below.
 *
 * Inputs MUST be JSON-safe values (object / array / string / finite number /
 * boolean / null). `undefined`-valued object members are omitted, matching
 * JSON semantics. Non-finite numbers (NaN, ±Infinity) are rejected — JCS has
 * no representation for them and silently coercing to null (as JSON.stringify
 * does) would let two distinct inputs canonicalize identically.
 */

/**
 * Canonicalize a JSON-safe value to its RFC 8785 string form.
 *
 * @param {*} value  A JSON-safe value (object/array/string/number/boolean/null)
 * @returns {string} The canonical JSON string (UTF-8 bytes when TextEncoder'd)
 */
export function jcsCanonicalize(value) {
  if (value === null) return 'null';

  const type = typeof value;

  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('jcsCanonicalize: non-finite numbers are not representable in JCS');
    }
    return JSON.stringify(value);
  }

  if (type === 'string' || type === 'boolean') {
    return JSON.stringify(value);
  }

  if (type === 'bigint') {
    // BigInt has no JSON representation and JSON.stringify throws on it; be
    // explicit rather than letting the throw surface from a confusing place.
    throw new TypeError('jcsCanonicalize: BigInt is not representable in JCS');
  }

  if (Array.isArray(value)) {
    // Array element order is significant and preserved. `undefined` / function
    // / symbol elements serialize to `null` in JSON; mirror that so array
    // length is preserved exactly as JSON.stringify would.
    const parts = value.map((el) => {
      if (el === undefined || typeof el === 'function' || typeof el === 'symbol') {
        return 'null';
      }
      return jcsCanonicalize(el);
    });
    return '[' + parts.join(',') + ']';
  }

  if (type === 'object') {
    // Recurse with keys sorted by UTF-16 code unit (default string sort).
    // Skip members whose value is undefined / function / symbol — JSON omits
    // these entirely (they do not become `null` inside objects).
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      const v = value[key];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
        continue;
      }
      parts.push(JSON.stringify(key) + ':' + jcsCanonicalize(v));
    }
    return '{' + parts.join(',') + '}';
  }

  // undefined / function / symbol at the top level: no JSON form.
  throw new TypeError(`jcsCanonicalize: value of type ${type} is not representable in JCS`);
}

/**
 * Canonicalize and UTF-8 encode in one step — the byte form fed to a signature
 * verify/sign call.
 *
 * @param {*} value  A JSON-safe value
 * @returns {Uint8Array} UTF-8 bytes of the canonical JSON
 */
export function jcsCanonicalizeBytes(value) {
  return new TextEncoder().encode(jcsCanonicalize(value));
}
