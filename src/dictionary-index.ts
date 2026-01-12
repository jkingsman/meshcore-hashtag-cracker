/**
 * DictionaryIndex - Precomputed hash-indexed wordlist for O(1) lookup
 *
 * Instead of checking every word in the dictionary for each packet,
 * we precompute the channel hash for each word and group them by hash.
 * This reduces dictionary lookup from O(n) to O(n/256) on average.
 */

import { deriveKeyFromRoomName, getChannelHash } from './core';

export interface IndexedWord {
  word: string;
  key: string; // Precomputed key hex
}

export class DictionaryIndex {
  // Map from channel hash byte (0-255) to words with that hash
  private byHash: Map<number, IndexedWord[]> = new Map();
  private totalWords: number = 0;

  constructor() {
    // Initialize empty buckets
    for (let i = 0; i < 256; i++) {
      this.byHash.set(i, []);
    }
  }

  /**
   * Build index from wordlist. This precomputes keys and channel hashes.
   * @param words - Array of room names (without # prefix)
   * @param onProgress - Optional progress callback
   */
  build(words: string[], onProgress?: (indexed: number, total: number) => void): void {
    this.totalWords = words.length;

    for (let i = 0; i < words.length; i++) {
      const word = words[i];
      const key = deriveKeyFromRoomName('#' + word);
      const channelHashHex = getChannelHash(key);
      const channelHash = parseInt(channelHashHex, 16);

      this.byHash.get(channelHash)!.push({ word, key });

      // Report progress every 10000 words
      if (onProgress && i % 10000 === 0) {
        onProgress(i, words.length);
      }
    }

    if (onProgress) {
      onProgress(words.length, words.length);
    }
  }

  /**
   * Look up all words matching a channel hash byte.
   * @param channelHash - The target channel hash (0-255)
   * @returns Array of words and their precomputed keys
   */
  lookup(channelHash: number): IndexedWord[] {
    return this.byHash.get(channelHash) ?? [];
  }

  /**
   * Get the total number of indexed words.
   */
  size(): number {
    return this.totalWords;
  }

  /**
   * Get statistics about the index distribution.
   */
  getStats(): { total: number; buckets: number; avgPerBucket: number; maxBucket: number } {
    let maxBucket = 0;
    let nonEmpty = 0;

    for (const [, words] of this.byHash) {
      if (words.length > 0) {
        nonEmpty++;
        maxBucket = Math.max(maxBucket, words.length);
      }
    }

    return {
      total: this.totalWords,
      buckets: nonEmpty,
      avgPerBucket: this.totalWords / 256,
      maxBucket,
    };
  }
}
