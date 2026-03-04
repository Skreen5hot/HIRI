/**
 * Base58 Encoding/Decoding
 *
 * Pure BigInt arithmetic implementation using the Bitcoin alphabet.
 * No external dependencies. Handles leading zero bytes correctly
 * (each leading 0x00 byte maps to a leading '1' character).
 *
 * This module is part of the kernel and MUST NOT perform I/O or
 * reference non-deterministic APIs.
 */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = BigInt(ALPHABET.length); // 58n

// Precompute reverse lookup
const ALPHABET_MAP = new Map<string, bigint>();
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP.set(ALPHABET[i], BigInt(i));
}

/**
 * Encode a byte array to a Base58 string.
 *
 * Leading zero bytes in the input produce leading '1' characters
 * in the output (the Bitcoin convention).
 *
 * @param bytes - The bytes to encode
 * @returns The Base58-encoded string
 */
export function encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  // Count leading zeros
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {
    leadingZeros++;
  }

  // Convert bytes to a single BigInt
  let num = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    num = num * 256n + BigInt(bytes[i]);
  }

  // Convert BigInt to base58 digits
  let result = "";
  while (num > 0n) {
    const remainder = num % BASE;
    num = num / BASE;
    result = ALPHABET[Number(remainder)] + result;
  }

  // Prepend '1' for each leading zero byte
  return ALPHABET[0].repeat(leadingZeros) + result;
}

/**
 * Decode a Base58 string to a byte array.
 *
 * Leading '1' characters in the input produce leading zero bytes
 * in the output.
 *
 * @param str - The Base58 string to decode
 * @returns The decoded bytes
 * @throws Error if the string contains invalid characters
 */
export function decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Count leading '1' characters (they map to 0x00 bytes)
  let leadingOnes = 0;
  while (leadingOnes < str.length && str[leadingOnes] === ALPHABET[0]) {
    leadingOnes++;
  }

  // Convert base58 string to BigInt
  let num = BigInt(0);
  for (let i = 0; i < str.length; i++) {
    const value = ALPHABET_MAP.get(str[i]);
    if (value === undefined) {
      throw new Error(`Invalid Base58 character: '${str[i]}' at position ${i}`);
    }
    num = num * BASE + value;
  }

  // Convert BigInt to bytes
  const byteArray: number[] = [];
  while (num > 0n) {
    byteArray.unshift(Number(num & 0xffn));
    num = num >> 8n;
  }

  // Prepend zero bytes for leading '1' characters
  const leadingBytes = new Array(leadingOnes).fill(0);
  return new Uint8Array([...leadingBytes, ...byteArray]);
}
