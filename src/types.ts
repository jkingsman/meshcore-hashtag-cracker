/**
 * Options for configuring the cracking process.
 */
export interface CrackOptions {
  /**
   * Maximum room name length to search (default: 8).
   * Longer names exponentially increase search time.
   */
  maxLength?: number;

  /**
   * Minimum room name length to search (default: 1).
   * Use this to skip shorter room names if you know the target is longer.
   */
  startingLength?: number;

  /**
   * Use dictionary attack before brute force (default: true).
   * When enabled and a wordlist is loaded, tries dictionary words first.
   * Set to false to skip dictionary attack even if a wordlist is loaded.
   */
  useDictionary?: boolean;

  /**
   * Filter results by timestamp validity (default: true).
   * When enabled, rejects results where the decrypted timestamp
   * is outside the validity window.
   */
  useTimestampFilter?: boolean;

  /**
   * Timestamp validity window in seconds (default: 2592000 = 30 days).
   * Only used when useTimestampFilter is enabled.
   * Timestamps older than this many seconds from now are rejected.
   */
  validSeconds?: number;

  /**
   * Filter results by UTF-8 validity (default: true).
   * When enabled, rejects results containing invalid UTF-8 sequences.
   */
  useUtf8Filter?: boolean;

  /**
   * Resume cracking from a specific position.
   * Useful for resuming interrupted searches.
   * The interpretation depends on startFromType.
   */
  startFrom?: string;

  /**
   * How to interpret the startFrom value (default: 'bruteforce').
   * - 'dictionary': startFrom is a dictionary word; resume dictionary attack from that word, then continue to brute force
   * - 'bruteforce': startFrom is a brute-force position; skip dictionary and resume brute force from that position
   */
  startFromType?: 'dictionary' | 'bruteforce';

  /**
   * Force CPU-based cracking instead of WebGPU (default: false).
   * Much slower but works in environments without WebGPU support.
   * Also useful for testing.
   */
  forceCpu?: boolean;
}

/**
 * Progress information reported during cracking.
 */
export interface ProgressReport {
  /** Total candidates checked so far */
  checked: number;

  /** Total candidates to check */
  total: number;

  /** Progress percentage (0-100) */
  percent: number;

  /** Current cracking rate in keys/second */
  rateKeysPerSec: number;

  /** Estimated time remaining in seconds */
  etaSeconds: number;

  /** Time elapsed since start in seconds */
  elapsedSeconds: number;

  /** Current room name length being tested */
  currentLength: number;

  /** Current room name position being tested */
  currentPosition: string;

  /** Current phase of cracking */
  phase: 'public-key' | 'wordlist' | 'bruteforce';
}

/**
 * Callback function for progress updates.
 * Called approximately 5 times per second during cracking.
 */
export type ProgressCallback = (report: ProgressReport) => void;

/**
 * Result of a cracking operation.
 */
export interface CrackResult {
  /** Whether a matching room name was found */
  found: boolean;

  /** The room name (without '#' prefix) if found */
  roomName?: string;

  /** The derived encryption key (hex) if found */
  key?: string;

  /** The decrypted message content if found */
  decryptedMessage?: string;

  /** Whether the operation was aborted */
  aborted?: boolean;

  /** Position to resume from if aborted or not found */
  resumeFrom?: string;

  /**
   * Type of resume position.
   * - 'dictionary': resumeFrom is a dictionary word
   * - 'bruteforce': resumeFrom is a brute-force position
   */
  resumeType?: 'dictionary' | 'bruteforce';

  /** Error message if an error occurred */
  error?: string;
}

/**
 * Decoded packet information extracted from a MeshCore GroupText packet.
 */
export interface DecodedPacket {
  /** Channel hash (1 byte, hex) */
  channelHash: string;

  /** Encrypted ciphertext (hex) */
  ciphertext: string;

  /** MAC for verification (2 bytes, hex) */
  cipherMac: string;

  /** Whether this is a GroupText packet */
  isGroupText: boolean;
}
