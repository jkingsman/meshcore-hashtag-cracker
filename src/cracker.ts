/**
 * GroupTextCracker - Standalone MeshCore GroupText packet cracker
 *
 * Cracks encrypted GroupText packets by trying room names until the
 * correct encryption key is found.
 */

import { MeshCorePacketDecoder, ChannelCrypto } from '@michaelhart/meshcore-decoder';
import { GpuBruteForce, isWebGpuSupported } from './gpu-bruteforce';
import { GpuWordPairs } from './gpu-wordpairs';
import { CpuBruteForce } from './cpu-bruteforce';
import {
  PUBLIC_ROOM_NAME,
  PUBLIC_KEY,
  DEFAULT_VALID_SECONDS,
  indexToRoomName,
  roomNameToIndex,
  deriveKeyFromRoomName,
  getChannelHash,
  verifyMac,
  countNamesForLength,
  isTimestampValid,
  isValidUtf8,
} from './core';
import type { CrackOptions, CrackResult, ProgressReport, ProgressCallback, DecodedPacket } from './types';

// Valid room name characters (for wordlist filtering)
const VALID_CHARS = /^[a-z0-9-]+$/;
const NO_DASH_AT_ENDS = /^[a-z0-9].*[a-z0-9]$|^[a-z0-9]$/;
const NO_CONSECUTIVE_DASHES = /--/;

function isValidRoomName(name: string): boolean {
  if (!name || name.length === 0) return false;
  if (!VALID_CHARS.test(name)) return false;
  if (name.length > 1 && !NO_DASH_AT_ENDS.test(name)) return false;
  if (NO_CONSECUTIVE_DASHES.test(name)) return false;
  return true;
}

/**
 * Main cracker class for MeshCore GroupText packets.
 */
export class GroupTextCracker {
  private gpuInstance: GpuBruteForce | null = null;
  private gpuWordPairs: GpuWordPairs | null = null;
  private cpuInstance: CpuBruteForce | null = null;
  private wordlist: string[] = [];
  private abortFlag = false;
  private useTimestampFilter = true;
  private useUtf8Filter = true;
  private useSenderFilter = true;
  private validSeconds = DEFAULT_VALID_SECONDS;
  private useCpu = false;

  /**
   * Load a wordlist from a URL for dictionary attacks.
   * The wordlist should be a text file with one word per line.
   *
   * @param url - URL to fetch the wordlist from
   */
  async loadWordlist(url: string): Promise<void> {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to load wordlist: ${response.status} ${response.statusText}`);
    }

    const text = await response.text();
    const allWords = text
      .split('\n')
      .map((w) => w.trim().toLowerCase())
      .filter((w) => w.length > 0);

    // Filter to valid room names only
    this.wordlist = allWords.filter(isValidRoomName);
  }

  /**
   * Set the wordlist directly from an array of words.
   *
   * @param words - Array of room names to try
   */
  setWordlist(words: string[]): void {
    this.wordlist = words
      .map((w) => w.trim().toLowerCase())
      .filter(isValidRoomName);
  }

  /**
   * Abort the current cracking operation.
   * The crack() method will return with aborted: true.
   */
  abort(): void {
    this.abortFlag = true;
  }

  /**
   * Check if WebGPU is available in the current environment.
   */
  isGpuAvailable(): boolean {
    return isWebGpuSupported();
  }

  /**
   * Decode a packet and extract the information needed for cracking.
   *
   * @param packetHex - The packet data as a hex string
   * @returns Decoded packet info or null if not a GroupText packet
   */
  async decodePacket(packetHex: string): Promise<DecodedPacket | null> {
    const cleanHex = packetHex.trim().replace(/\s+/g, '').replace(/^0x/i, '');

    if (!cleanHex || !/^[0-9a-fA-F]+$/.test(cleanHex)) {
      return null;
    }

    try {
      const decoded = await MeshCorePacketDecoder.decodeWithVerification(cleanHex, {});
      const payload = decoded.payload?.decoded as {
        channelHash?: string;
        ciphertext?: string;
        cipherMac?: string;
      } | null;

      if (!payload?.channelHash || !payload?.ciphertext || !payload?.cipherMac) {
        return null;
      }

      return {
        channelHash: payload.channelHash,
        ciphertext: payload.ciphertext,
        cipherMac: payload.cipherMac,
        isGroupText: true,
      };
    } catch {
      return null;
    }
  }

  /**
   * Crack a GroupText packet to find the room name and decrypt the message.
   *
   * @param packetHex - The packet data as a hex string
   * @param options - Cracking options
   * @param onProgress - Optional callback for progress updates
   * @returns The cracking result
   */
  async crack(
    packetHex: string,
    options?: CrackOptions,
    onProgress?: ProgressCallback,
  ): Promise<CrackResult> {
    this.abortFlag = false;
    this.useTimestampFilter = options?.useTimestampFilter ?? true;
    this.useUtf8Filter = options?.useUtf8Filter ?? true;
    this.useSenderFilter = options?.useSenderFilter ?? true;
    this.validSeconds = options?.validSeconds ?? DEFAULT_VALID_SECONDS;
    this.useCpu = options?.forceCpu ?? false;
    const maxLength = options?.maxLength ?? 8;
    const startingLength = options?.startingLength ?? 1;
    const useDictionary = options?.useDictionary ?? true;
    const useTwoWordCombinations = options?.useTwoWordCombinations ?? false;
    const startFromType = options?.startFromType ?? 'bruteforce';

    // Normalize packet hex to lowercase for consistent processing
    const normalizedPacketHex = packetHex.toLowerCase();

    // Decode packet
    const decoded = await this.decodePacket(normalizedPacketHex);
    if (!decoded) {
      return { found: false, error: 'Invalid packet or not a GroupText packet' };
    }

    const { channelHash, ciphertext, cipherMac } = decoded;
    const targetHashByte = parseInt(channelHash, 16);

    // Initialize GPU or CPU instance
    if (this.useCpu) {
      // Use CPU fallback
      if (!this.cpuInstance) {
        this.cpuInstance = new CpuBruteForce();
      }
    } else {
      // Try GPU, fall back to CPU if not available
      if (!this.gpuInstance) {
        this.gpuInstance = new GpuBruteForce();
        const gpuOk = await this.gpuInstance.init();
        if (!gpuOk) {
          // GPU not available, fall back to CPU
          this.useCpu = true;
          this.cpuInstance = new CpuBruteForce();
        }
      }
    }

    const startTime = performance.now();
    let totalChecked = 0;
    let lastProgressUpdate = performance.now();

    // Determine starting position for brute force
    let startFromLength = startingLength;
    let startFromOffset = 0;
    let dictionaryStartIndex = 0;
    let skipDictionary = false;
    let skipWordPairs = false;
    let wordPairStartI = 0;
    let wordPairStartJ = 0;

    if (options?.startFrom) {
      // Normalize to lowercase for consistent matching
      const normalizedStartFrom = options.startFrom.toLowerCase();

      if (startFromType === 'dictionary') {
        // Find the word in the dictionary and start AFTER it (like brute force does)
        const wordIndex = this.wordlist.indexOf(normalizedStartFrom);
        if (wordIndex >= 0) {
          dictionaryStartIndex = wordIndex + 1; // Start after the given word
        }
        // If word not found, start dictionary from beginning
      } else if (startFromType === 'dictionary-pair') {
        // Resume from a two-word combination (format: "word1+word2")
        // Note: actual indices will be resolved later after shortWords is built
        skipDictionary = true;
        // Store the words to find later - indices will be set after shortWords is populated
        const plusIndex = normalizedStartFrom.indexOf('+');
        if (plusIndex > 0) {
          // Store for later resolution
          (options as { _pairResumeWord1?: string; _pairResumeWord2?: string })._pairResumeWord1 = normalizedStartFrom.substring(0, plusIndex);
          (options as { _pairResumeWord1?: string; _pairResumeWord2?: string })._pairResumeWord2 = normalizedStartFrom.substring(plusIndex + 1);
        }
      } else {
        // Brute force resume: skip dictionary and word pairs entirely
        skipDictionary = true;
        skipWordPairs = true;
        const pos = roomNameToIndex(normalizedStartFrom);
        if (pos) {
          startFromLength = Math.max(startingLength, pos.length);
          startFromOffset = pos.index + 1; // Start after the given position
          if (startFromOffset >= countNamesForLength(startFromLength)) {
            startFromLength++;
            startFromOffset = 0;
          }
        }
      }
    }

    // Calculate total candidates for progress
    // Include remaining dictionary words if not skipping dictionary
    let totalCandidates = 0;
    if (useDictionary && !skipDictionary && this.wordlist.length > 0) {
      totalCandidates += this.wordlist.length - dictionaryStartIndex;
    }

    // For two-word combinations, pre-filter to short words only (max length 15 each for 30 combined)
    // This dramatically reduces the search space and makes counting O(N) instead of O(N²)
    const MAX_COMBINED_LENGTH = 30;
    const MAX_SINGLE_WORD_LENGTH = 15;
    let shortWords: string[] = [];
    let shortWordLengths: number[] = [];
    let wordPairCount = 0;

    // Build length buckets for O(N) pair counting: lengthBuckets[len] = count of words with that length
    let lengthBuckets: number[] = [];
    // Cumulative counts: wordsAtMostLength[len] = count of words with length <= len
    let wordsAtMostLength: number[] = [];

    if (useDictionary && useTwoWordCombinations && !skipWordPairs && this.wordlist.length > 0) {
      // Filter to short words only
      shortWords = this.wordlist.filter(w => w.length <= MAX_SINGLE_WORD_LENGTH);
      shortWordLengths = shortWords.map(w => w.length);

      // Resolve dictionary-pair resume indices now that shortWords is built
      const pairOpts = options as { _pairResumeWord1?: string; _pairResumeWord2?: string };
      if (pairOpts._pairResumeWord1 && pairOpts._pairResumeWord2) {
        const idx1 = shortWords.indexOf(pairOpts._pairResumeWord1);
        const idx2 = shortWords.indexOf(pairOpts._pairResumeWord2);
        if (idx1 >= 0 && idx2 >= 0) {
          wordPairStartI = idx1;
          wordPairStartJ = idx2 + 1;
          if (wordPairStartJ >= shortWords.length) {
            wordPairStartI++;
            wordPairStartJ = 0;
          }
        }
      }

      // Build length buckets
      lengthBuckets = new Array(MAX_SINGLE_WORD_LENGTH + 1).fill(0);
      for (const len of shortWordLengths) {
        lengthBuckets[len]++;
      }

      // Build cumulative counts
      wordsAtMostLength = new Array(MAX_COMBINED_LENGTH + 1).fill(0);
      let cumulative = 0;
      for (let len = 0; len <= MAX_COMBINED_LENGTH; len++) {
        if (len <= MAX_SINGLE_WORD_LENGTH) {
          cumulative += lengthBuckets[len];
        }
        wordsAtMostLength[len] = cumulative;
      }

      // Count pairs efficiently: for each word of length L, it can pair with any word of length <= (30 - L)
      // This is O(N) instead of O(N²)
      for (let i = wordPairStartI; i < shortWords.length; i++) {
        const len1 = shortWordLengths[i];
        const maxLen2 = MAX_COMBINED_LENGTH - len1;
        const countForThisWord = wordsAtMostLength[Math.min(maxLen2, MAX_SINGLE_WORD_LENGTH)];

        if (i === wordPairStartI && wordPairStartJ > 0) {
          // Partial first row - subtract words we're skipping
          wordPairCount += Math.max(0, countForThisWord - wordPairStartJ);
        } else {
          wordPairCount += countForThisWord;
        }
      }

      totalCandidates += wordPairCount;
    }

    // Add brute force candidates
    for (let l = startFromLength; l <= maxLength; l++) {
      totalCandidates += countNamesForLength(l);
    }
    totalCandidates -= startFromOffset;

    // Helper to report progress
    const reportProgress = (
      phase: ProgressReport['phase'],
      currentLength: number,
      currentPosition: string,
    ) => {
      if (!onProgress) return;

      const now = performance.now();
      const elapsed = (now - startTime) / 1000;
      const rate = elapsed > 0 ? Math.round(totalChecked / elapsed) : 0;
      const remaining = totalCandidates - totalChecked;
      const eta = rate > 0 ? remaining / rate : 0;

      onProgress({
        checked: totalChecked,
        total: totalCandidates,
        percent: totalCandidates > 0 ? Math.min(100, (totalChecked / totalCandidates) * 100) : 0,
        rateKeysPerSec: rate,
        etaSeconds: eta,
        elapsedSeconds: elapsed,
        currentLength,
        currentPosition,
        phase,
      });
    };

    // Helper to verify MAC and filters
    const verifyMacAndFilters = (
      key: string,
    ): { valid: boolean; message?: string } => {
      if (!verifyMac(ciphertext, cipherMac, key)) {
        return { valid: false };
      }

      const result = ChannelCrypto.decryptGroupTextMessage(ciphertext, cipherMac, key);
      if (!result.success || !result.data) {
        return { valid: false };
      }

      if (this.useTimestampFilter && !isTimestampValid(result.data.timestamp, this.validSeconds)) {
        return { valid: false };
      }

      if (this.useUtf8Filter && !isValidUtf8(result.data.message)) {
        return { valid: false };
      }

      if (this.useSenderFilter && !result.data.sender) {
        return { valid: false };
      }

      // Format message with sender prefix if available
      const fullMessage = result.data.sender
        ? `${result.data.sender}: ${result.data.message}`
        : result.data.message;

      return { valid: true, message: fullMessage };
    };

    // Phase 1: Try public key (only if not resuming)
    if (!skipDictionary && dictionaryStartIndex === 0 && startFromLength === startingLength && startFromOffset === 0) {
      reportProgress('public-key', 0, PUBLIC_ROOM_NAME);

      const publicChannelHash = getChannelHash(PUBLIC_KEY);
      if (channelHash === publicChannelHash) {
        const result = verifyMacAndFilters(PUBLIC_KEY);
        if (result.valid) {
          return {
            found: true,
            roomName: PUBLIC_ROOM_NAME,
            key: PUBLIC_KEY,
            decryptedMessage: result.message,
          };
        }
      }
    }

    // Phase 2: Dictionary attack
    if (useDictionary && !skipDictionary && this.wordlist.length > 0) {
      for (let i = dictionaryStartIndex; i < this.wordlist.length; i++) {
        if (this.abortFlag) {
          return {
            found: false,
            aborted: true,
            resumeFrom: this.wordlist[i],
            resumeType: 'dictionary',
          };
        }

        const word = this.wordlist[i];
        const key = deriveKeyFromRoomName('#' + word);
        const wordChannelHash = getChannelHash(key);

        if (parseInt(wordChannelHash, 16) === targetHashByte) {
          const result = verifyMacAndFilters(key);
          if (result.valid) {
            return {
              found: true,
              roomName: word,
              key,
              decryptedMessage: result.message,
              // Include resume info so caller can skip this result and continue
              resumeFrom: word,
              resumeType: 'dictionary',
            };
          }
        }

        totalChecked++;

        // Progress update
        const now = performance.now();
        if (now - lastProgressUpdate >= 200) {
          reportProgress('wordlist', word.length, word);
          lastProgressUpdate = now;
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }
    }

    // Phase 2.5: Two-word combinations (EXPERIMENTAL)
    // Uses pre-filtered shortWords (words with length <= 15) for efficiency
    // GPU-accelerated when available
    if (useDictionary && useTwoWordCombinations && !skipWordPairs && shortWords.length > 0) {
      const totalPairs = shortWords.length * shortWords.length;
      const startPairIdx = wordPairStartI * shortWords.length + wordPairStartJ;

      // Try GPU acceleration for word pairs
      let useGpuForPairs = !this.useCpu;
      if (useGpuForPairs) {
        if (!this.gpuWordPairs) {
          this.gpuWordPairs = new GpuWordPairs();
          const gpuOk = await this.gpuWordPairs.init();
          if (!gpuOk) {
            useGpuForPairs = false;
            this.gpuWordPairs = null;
          }
        }
        if (this.gpuWordPairs) {
          this.gpuWordPairs.uploadWords(shortWords);
        }
      }

      if (useGpuForPairs && this.gpuWordPairs) {
        // GPU-accelerated word pair checking
        // Start with 1M pairs (like Python/OpenCL version) for better throughput
        const INITIAL_PAIR_BATCH_SIZE = 1048576;  // 1M
        // WebGPU limits dispatchWorkgroups to 65535 per dimension
        // With workgroup_size(256) and 32 pairs/thread: 65535 * 256 * 32 = 536,870,880
        const MAX_PAIR_BATCH_SIZE = 65535 * 256 * 32;
        const TARGET_PAIR_DISPATCH_MS = options?.gpuDispatchMs ?? 1000;
        let pairBatchSize = INITIAL_PAIR_BATCH_SIZE;
        let pairBatchTuned = false;
        let pairOffset = startPairIdx;

        while (pairOffset < totalPairs) {
          if (this.abortFlag) {
            const i = Math.floor(pairOffset / shortWords.length);
            const j = pairOffset % shortWords.length;
            return {
              found: false,
              aborted: true,
              resumeFrom: `${shortWords[i]}+${shortWords[j]}`,
              resumeType: 'dictionary-pair',
            };
          }

          const batchSize = Math.min(pairBatchSize, totalPairs - pairOffset);
          const dispatchStart = performance.now();

          const matches = await this.gpuWordPairs.runBatch(
            targetHashByte,
            pairOffset,
            batchSize,
            ciphertext,
            cipherMac,
          );

          const dispatchTime = performance.now() - dispatchStart;
          totalChecked += batchSize;

          // Auto-tune batch size
          if (!pairBatchTuned && batchSize >= INITIAL_PAIR_BATCH_SIZE && dispatchTime > 0) {
            const scaleFactor = TARGET_PAIR_DISPATCH_MS / dispatchTime;
            const optimalBatchSize = Math.round(batchSize * scaleFactor);
            const rounded = Math.pow(
              2,
              Math.round(Math.log2(Math.max(INITIAL_PAIR_BATCH_SIZE, optimalBatchSize))),
            );
            pairBatchSize = Math.min(Math.max(INITIAL_PAIR_BATCH_SIZE, rounded), MAX_PAIR_BATCH_SIZE);
            pairBatchTuned = true;
          }

          // Check matches
          for (const [i, j] of matches) {
            const word1 = shortWords[i];
            const word2 = shortWords[j];
            const combined = word1 + word2;
            const key = deriveKeyFromRoomName('#' + combined);
            const result = verifyMacAndFilters(key);
            if (result.valid) {
              return {
                found: true,
                roomName: combined,
                key,
                decryptedMessage: result.message,
                resumeFrom: `${word1}+${word2}`,
                resumeType: 'dictionary-pair',
              };
            }
          }

          pairOffset += batchSize;

          // Progress update
          const now = performance.now();
          if (now - lastProgressUpdate >= 200) {
            const i = Math.floor(Math.min(pairOffset, totalPairs - 1) / shortWords.length);
            const j = Math.min(pairOffset, totalPairs - 1) % shortWords.length;
            reportProgress('wordlist-pairs', 0, `${shortWords[i]}+${shortWords[j]}`);
            lastProgressUpdate = now;
            await new Promise((resolve) => setTimeout(resolve, 0));
          }
        }
      } else {
        // CPU fallback for word pairs
        for (let i = wordPairStartI; i < shortWords.length; i++) {
          const word1 = shortWords[i];
          const len1 = shortWordLengths[i];
          const maxLen2 = MAX_COMBINED_LENGTH - len1;

          const startJ = i === wordPairStartI ? wordPairStartJ : 0;

          for (let j = startJ; j < shortWords.length; j++) {
            if (this.abortFlag) {
              return {
                found: false,
                aborted: true,
                resumeFrom: `${word1}+${shortWords[j]}`,
                resumeType: 'dictionary-pair',
              };
            }

            const len2 = shortWordLengths[j];
            if (len2 > maxLen2) continue;

            const word2 = shortWords[j];
            const combined = word1 + word2;

            // Validate combined name (check for consecutive dashes at join point)
            if (!isValidRoomName(combined)) continue;

            const key = deriveKeyFromRoomName('#' + combined);
            const pairChannelHash = getChannelHash(key);

            if (parseInt(pairChannelHash, 16) === targetHashByte) {
              const result = verifyMacAndFilters(key);
              if (result.valid) {
                return {
                  found: true,
                  roomName: combined,
                  key,
                  decryptedMessage: result.message,
                  resumeFrom: `${word1}+${word2}`,
                  resumeType: 'dictionary-pair',
                };
              }
            }

            totalChecked++;

            // Progress update
            const now = performance.now();
            if (now - lastProgressUpdate >= 200) {
              reportProgress('wordlist-pairs', len1 + len2, `${word1}+${word2}`);
              lastProgressUpdate = now;
              await new Promise((resolve) => setTimeout(resolve, 0));
            }
          }
        }
      }
    }

    // Phase 3: Brute force (GPU or CPU)
    // Use smaller batches for CPU since it's much slower
    const INITIAL_BATCH_SIZE = this.useCpu ? 1024 : 32768;
    // WebGPU limits dispatchWorkgroups to 65535 per dimension
    // With workgroup_size(256) and 32 candidates/thread: 65535 * 256 * 32 = 536,870,880
    const MAX_BATCH_SIZE = 65535 * 256 * 32;
    const TARGET_DISPATCH_MS = options?.gpuDispatchMs ?? 1000;
    let currentBatchSize = INITIAL_BATCH_SIZE;
    let batchSizeTuned = false;

    for (let length = startFromLength; length <= maxLength; length++) {
      if (this.abortFlag) {
        const resumePos = indexToRoomName(length, 0);
        return {
          found: false,
          aborted: true,
          resumeFrom: resumePos || undefined,
          resumeType: 'bruteforce',
        };
      }

      const totalForLength = countNamesForLength(length);
      let offset = length === startFromLength ? startFromOffset : 0;

      while (offset < totalForLength) {
        if (this.abortFlag) {
          const resumePos = indexToRoomName(length, offset);
          return {
            found: false,
            aborted: true,
            resumeFrom: resumePos || undefined,
            resumeType: 'bruteforce',
          };
        }

        const batchSize = Math.min(currentBatchSize, totalForLength - offset);
        const dispatchStart = performance.now();

        // Run batch on GPU or CPU
        let matches: number[];
        if (this.useCpu) {
          matches = this.cpuInstance!.runBatch(
            targetHashByte,
            length,
            offset,
            batchSize,
            ciphertext,
            cipherMac,
          );
        } else {
          matches = await this.gpuInstance!.runBatch(
            targetHashByte,
            length,
            offset,
            batchSize,
            ciphertext,
            cipherMac,
          );
        }

        const dispatchTime = performance.now() - dispatchStart;
        totalChecked += batchSize;

        // Auto-tune batch size (GPU only)
        if (!this.useCpu && !batchSizeTuned && batchSize >= INITIAL_BATCH_SIZE && dispatchTime > 0) {
          const scaleFactor = TARGET_DISPATCH_MS / dispatchTime;
          const optimalBatchSize = Math.round(batchSize * scaleFactor);
          const rounded = Math.pow(
            2,
            Math.round(Math.log2(Math.max(INITIAL_BATCH_SIZE, optimalBatchSize))),
          );
          currentBatchSize = Math.min(Math.max(INITIAL_BATCH_SIZE, rounded), MAX_BATCH_SIZE);
          batchSizeTuned = true;
        }

        // Check matches
        for (const matchIdx of matches) {
          const roomName = indexToRoomName(length, matchIdx);
          if (!roomName) continue;

          const key = deriveKeyFromRoomName('#' + roomName);
          const result = verifyMacAndFilters(key);
          if (result.valid) {
            return {
              found: true,
              roomName,
              key,
              decryptedMessage: result.message,
              // Include resume info so caller can skip this result and continue
              resumeFrom: roomName,
              resumeType: 'bruteforce',
            };
          }
        }

        offset += batchSize;

        // Progress update
        const now = performance.now();
        if (now - lastProgressUpdate >= 200) {
          const currentPos = indexToRoomName(length, Math.min(offset, totalForLength - 1)) || '';
          reportProgress('bruteforce', length, currentPos);
          lastProgressUpdate = now;
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }
    }

    // Not found
    const lastPos = indexToRoomName(maxLength, countNamesForLength(maxLength) - 1);
    return {
      found: false,
      resumeFrom: lastPos || undefined,
      resumeType: 'bruteforce',
    };
  }

  /**
   * Clean up resources.
   * Call this when you're done using the cracker.
   */
  destroy(): void {
    if (this.gpuInstance) {
      this.gpuInstance.destroy();
      this.gpuInstance = null;
    }
    if (this.gpuWordPairs) {
      this.gpuWordPairs.destroy();
      this.gpuWordPairs = null;
    }
    if (this.cpuInstance) {
      this.cpuInstance.destroy();
      this.cpuInstance = null;
    }
  }
}
