import { mkdir, writeFile } from 'node:fs/promises';
import { deflateSync } from 'node:zlib';

const directory = new URL('../extension/icons/', import.meta.url);
await mkdir(directory, { recursive: true });

function chunk(type, data) {
  const content = Buffer.concat([Buffer.from(type), data]);
  let crc = 0xffffffff;
  for (const byte of content) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  const length = Buffer.alloc(4);
  const checksum = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  checksum.writeUInt32BE((crc ^ 0xffffffff) >>> 0);
  return Buffer.concat([length, content, checksum]);
}

function distance(x, y, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx ** 2 + dy ** 2)));
  return Math.hypot(x - ax - t * dx, y - ay - t * dy);
}

function pixel(x, y) {
  const halfWidth = y < 23 ? 39 * (y - 5) / 18
    : y < 49 ? 39 : 39 * Math.sqrt(Math.max(0, 1 - ((y - 49) / 47) ** 2));
  if (Math.abs(x - 50) >= halfWidth || y >= 96) return null;
  if (distance(x, y, 33, 51, 45, 63) < 4.7 || distance(x, y, 45, 63, 69, 38) < 4.7) {
    return [201, 162, 39];
  }
  return [11, 31, 58];
}

for (const size of [16, 32, 48, 128]) {
  const stride = 1 + size * 4;
  const rows = Buffer.alloc(size * stride);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const sum = [0, 0, 0];
      let covered = 0;
      for (let dy = 0; dy < 4; dy++) {
        for (let dx = 0; dx < 4; dx++) {
          const sample = pixel((x + (dx + 0.5) / 4) * 100 / size, (y + (dy + 0.5) / 4) * 100 / size);
          if (!sample) continue;
          covered++;
          sample.forEach((value, index) => { sum[index] += value; });
        }
      }
      const offset = y * stride + 1 + x * 4;
      if (covered) sum.forEach((value, index) => { rows[offset + index] = Math.round(value / covered); });
      rows[offset + 3] = Math.round(255 * covered / 16);
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  await writeFile(new URL(`shield-${size}.png`, directory), Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', header), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0)),
  ]));
}
