// Generates icons/icon-{16,32,48,128}.png (green shield with a white keyhole). No dependencies.
// Run: node scripts/make-icons.js
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const CRC_TABLE = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc32 = buf => {
  let c = -1;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
};
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0))
  ]);
}

// Shape tests in normalized coordinates (0..1).
function inShield(x, y) {
  const cx = 0.5,
    top = 0.07,
    mid = 0.52,
    bottom = 0.95,
    half = 0.4;
  if (y < top || y > bottom) return false;
  const dx = Math.abs(x - cx);
  if (y <= mid) {
    const dip = 0.05 * Math.sin(((x - 0.1) / 0.8) * Math.PI); // gentle top curve
    return dx <= half && y >= top + Math.max(0, 0.05 - dip);
  }
  const t = (y - mid) / (bottom - mid);
  return dx <= half * Math.sqrt(Math.max(0, 1 - t * t));
}
function inKeyhole(x, y) {
  const cx = 0.5,
    cy = 0.42;
  if ((x - cx) ** 2 + (y - cy) ** 2 <= 0.11 ** 2) return true;
  return y >= cy && y <= 0.7 && Math.abs(x - cx) <= 0.045 + (y - cy) * 0.12;
}

function render(size) {
  const buf = Buffer.alloc(size * size * 4);
  const S = 4; // supersampling
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let shield = 0,
        hole = 0;
      for (let sy = 0; sy < S; sy++)
        for (let sx = 0; sx < S; sx++) {
          const x = (px + (sx + 0.5) / S) / size,
            y = (py + (sy + 0.5) / S) / size;
          if (inShield(x, y)) {
            if (inKeyhole(x, y)) hole++;
            else shield++;
          }
        }
      const total = S * S,
        a = (shield + hole) / total;
      const i = (py * size + px) * 4;
      if (!a) continue;
      const w = hole / (shield + hole); // white fraction
      buf[i] = Math.round(23 * (1 - w) + 255 * w);
      buf[i + 1] = Math.round(107 * (1 - w) + 255 * w);
      buf[i + 2] = Math.round(85 * (1 - w) + 255 * w);
      buf[i + 3] = Math.round(a * 255);
    }
  }
  return png(size, buf);
}

const out = path.join(__dirname, "..", "icons");
fs.mkdirSync(out, { recursive: true });
for (const s of [16, 32, 48, 128]) fs.writeFileSync(path.join(out, `icon-${s}.png`), render(s));
console.log("Icons written to", out);
