import { copyFile, mkdir } from 'node:fs/promises';

const engine = new URL('../extension/engine/', import.meta.url);
await mkdir(engine, { recursive: true });
await copyFile(new URL('../public/engine/scamshield.js', import.meta.url),
  new URL('scamshield.js', engine));
