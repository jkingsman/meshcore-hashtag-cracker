/**
 * GroupTextCracker - Standalone MeshCore GroupText packet cracker
 *
 * Cracks encrypted GroupText packets by trying room names until the
 * correct encryption key is found.
 */

import { MeshCorePacketDecoder, ChannelCrypto } from '@michaelhart/meshcore-decoder';
import { GpuBruteForce, isWebGpuSupported } from './gpu-bruteforce';
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
  private cpuInstance: CpuBruteForce | null = null;
  private wordlist: string[] = [];
  private abortFlag = false;
  private useTimestampFilter = true;
  private useUtf8Filter = true;
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
    this.validSeconds = options?.validSeconds ?? DEFAULT_VALID_SECONDS;
    this.useCpu = options?.forceCpu ?? false;
    const maxLength = options?.maxLength ?? 8;
    const startingLength = options?.startingLength ?? 1;
    const useDictionary = options?.useDictionary ?? true;
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
      } else {
        // Brute force resume: skip dictionary entirely
        skipDictionary = true;
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

      return { valid: true, message: result.data.message };
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

    // Phase 3: Brute force (GPU or CPU)
    // Use smaller batches for CPU since it's much slower
    const INITIAL_BATCH_SIZE = this.useCpu ? 1024 : 32768;
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
          currentBatchSize = Math.max(INITIAL_BATCH_SIZE, rounded);
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
    if (this.cpuInstance) {
      this.cpuInstance.destroy();
      this.cpuInstance = null;
    }
  }
}
