/**
 * Build script for browser bundle (meshcore_cracker.min.js)
 * Creates a self-contained, minified bundle for direct browser inclusion.
 */

import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'iife',
  globalName: 'MeshCoreCracker',
  outfile: 'browser/meshcore_cracker.min.js',
  sourcemap: true,
  target: 'es2020',
  platform: 'browser',
  minify: true,
  banner: {
    js: `/**
 * MeshCore Hashtag Room Cracker v1.0.0
 * https://github.com/jkingsman/meshcore-hashtag-cracker
 *
 * Copyright (c) 2026 Jack Kingsman
 * Licensed under MIT
 *
 * Includes:
 * - crypto-js (c) 2009-2013 Jeff Mott, 2013-2016 Evan Vosberg (MIT)
 * - @michaelhart/meshcore-decoder (c) 2025 Michael Hart (MIT)
 * - @noble/ed25519 (c) 2019 Paul Miller (MIT)
 *
 * See LICENSE.md for full license texts.
 */`,
  },
});

console.log('Browser bundle complete: browser/meshcore_cracker.min.js');
