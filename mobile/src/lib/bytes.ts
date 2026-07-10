// Byte helpers bridging the uniffi ArrayBuffer API, the number[] key format
// shared with the desktop keystore JSON, and UTF-8 text. Implemented by hand
// because Hermes does not ship TextEncoder/TextDecoder on all versions.

export function bytesToBuffer(bytes: number[] | Uint8Array): ArrayBuffer {
  const u8 = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

export function bufferToBytes(buffer: ArrayBuffer): number[] {
  return Array.from(new Uint8Array(buffer));
}

export function utf8Encode(text: string): ArrayBuffer {
  const out: number[] = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
    }
  }
  return bytesToBuffer(out);
}

export function utf8Decode(buffer: ArrayBuffer | Uint8Array): string {
  const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let result = '';
  let i = 0;
  while (i < u8.length) {
    const b0 = u8[i]!;
    let cp: number;
    if (b0 < 0x80) {
      cp = b0;
      i += 1;
    } else if ((b0 & 0xe0) === 0xc0) {
      cp = ((b0 & 0x1f) << 6) | (u8[i + 1]! & 0x3f);
      i += 2;
    } else if ((b0 & 0xf0) === 0xe0) {
      cp = ((b0 & 0x0f) << 12) | ((u8[i + 1]! & 0x3f) << 6) | (u8[i + 2]! & 0x3f);
      i += 3;
    } else {
      cp =
        ((b0 & 0x07) << 18) |
        ((u8[i + 1]! & 0x3f) << 12) |
        ((u8[i + 2]! & 0x3f) << 6) |
        (u8[i + 3]! & 0x3f);
      i += 4;
    }
    result += String.fromCodePoint(cp);
  }
  return result;
}

export function groupFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{1,4}/g)?.join(' ') ?? fingerprint;
}
