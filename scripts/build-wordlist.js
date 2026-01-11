#!/usr/bin/env node

/**
 * Generates src/wordlist.ts from src/words.txt
 * Filters words to valid MeshCore room name format
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcDir = join(__dirname, '..', 'src');

// Read raw wordlist
const rawWords = readFileSync(join(srcDir, 'words.txt'), 'utf-8');

// Valid room name pattern: a-z0-9, dashes allowed but not at start/end, no consecutive dashes
const validRoomName = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;

const words = rawWords
  .split(/\r?\n/)
  .map(w => w.trim().toLowerCase())
  .filter(w => w.length > 0 && validRoomName.test(w) && !w.includes('--'));

console.log(`Filtered ${rawWords.split('\n').length} words to ${words.length} valid room names`);

// Generate TypeScript file
const output = `/**
 * English wordlist for dictionary attacks
 * Auto-generated from words.txt - do not edit manually
 *
 * @example
 * \`\`\`typescript
 * import { ENGLISH_WORDLIST } from 'meshcore-hashtag-cracker/wordlist';
 * cracker.setWordlist(ENGLISH_WORDLIST);
 * \`\`\`
 */
export const ENGLISH_WORDLIST: string[] = ${JSON.stringify(words)};
`;

writeFileSync(join(srcDir, 'wordlist.ts'), output);
console.log(`Generated src/wordlist.ts (${(output.length / 1024 / 1024).toFixed(2)} MB)`);
