# API Reference

## GroupTextCracker

Main class for cracking GroupText packets.

### Methods

#### `crack(packetHex, options?, onProgress?): Promise<CrackResult>`

Crack a GroupText packet to find the room name and decrypt the message.

**Parameters:**
- `packetHex: string` - The packet data as a hex string
- `options?: CrackOptions` - Cracking options
- `onProgress?: ProgressCallback` - Optional progress callback

**Returns:** `Promise<CrackResult>`

#### `loadWordlist(url: string): Promise<void>`

Load a wordlist from a URL for dictionary attacks.

#### `setWordlist(words: string[]): void`

Set the wordlist directly from an array.

#### `abort(): void`

Abort the current cracking operation.

#### `isGpuAvailable(): boolean`

Check if WebGPU is available.

#### `destroy(): void`

Clean up GPU resources.

## Types

### CrackOptions

```typescript
interface CrackOptions {
  maxLength?: number;           // Max room name length (default: 8)
  startingLength?: number;      // Min room name length (default: 1)
  useDictionary?: boolean;      // Use dictionary attack (default: true)
  useTimestampFilter?: boolean; // Filter old timestamps (default: true)
  validSeconds?: number;        // Timestamp validity window in seconds (default: 2592000 = 30 days)
  useUtf8Filter?: boolean;      // Filter invalid UTF-8 (default: true)
  startFrom?: string;           // Resume from position
  forceCpu?: boolean;           // Force CPU-based cracking (default: false)
}
```

### CrackResult

```typescript
interface CrackResult {
  found: boolean;
  roomName?: string;          // Room name without '#'
  key?: string;               // Encryption key (hex)
  decryptedMessage?: string;  // Decrypted message
  aborted?: boolean;          // Was operation aborted
  resumeFrom?: string;        // Position for resume
  error?: string;             // Error message
}
```

### ProgressReport

```typescript
interface ProgressReport {
  checked: number;           // Candidates checked
  total: number;             // Total candidates
  percent: number;           // Progress 0-100
  rateKeysPerSec: number;    // Current rate
  etaSeconds: number;        // Estimated time remaining
  elapsedSeconds: number;    // Time elapsed
  currentLength: number;     // Current room name length
  currentPosition: string;   // Current position
  phase: 'public-key' | 'wordlist' | 'bruteforce';
}
```

## Validation Filters

The cracker uses two filters to quickly reject false positives and improve accuracy:

### Timestamp Filter

`useTimestampFilter` (default: `true`)

MeshCore packets contain a timestamp field. When a candidate key decrypts the packet, the timestamp filter checks whether the resulting timestamp falls within the validity window. If the decrypted timestamp is far in the past or future, it indicates the wrong key was used and the candidate is rejected. This dramatically reduces false positives since random decryption rarely produces a plausible recent timestamp.

The validity window can be customized using the `validSeconds` option (default: 2592000 seconds = 30 days). For example, to only accept packets from the last hour:

```typescript
const result = await cracker.crack(packetHex, {
  useTimestampFilter: true,
  validSeconds: 3600, // 1 hour
});
```

### UTF-8 Filter

`useUtf8Filter` (default: `true`)

When decrypting with an incorrect key, the resulting bytes are essentially random and often form invalid UTF-8 sequences. The UTF-8 filter checks whether the decrypted message contains the Unicode replacement character (`U+FFFD`), which appears when bytes cannot be decoded as valid UTF-8. Messages containing this character are rejected as false positives.

Both filters are enabled by default and work together to ensure that only genuinely valid decryptions are returned. You can disable them if needed, but this may result in false positive matches.

## CPU Fallback

By default, the cracker uses WebGPU for hardware-accelerated brute force. If WebGPU is not available, it automatically falls back to CPU-based cracking.

You can force CPU mode with the `forceCpu` option:

```typescript
const result = await cracker.crack(packetHex, {
  forceCpu: true,  // Use CPU even if GPU is available
  maxLength: 4,    // Keep maxLength low for CPU - it's much slower
});
```

CPU mode is useful for:
- Environments without WebGPU (Node.js, older browsers)
- Testing and debugging
- Short room names where GPU overhead isn't worthwhile

## Usage Examples

### With Progress Callback

```typescript
const result = await cracker.crack(packetHex, {
  maxLength: 8,
  useTimestampFilter: true,
  useUtf8Filter: true,
}, (progress) => {
  console.log(`Progress: ${progress.percent.toFixed(1)}%`);
  console.log(`Rate: ${(progress.rateKeysPerSec / 1e6).toFixed(2)} Mkeys/s`);
  console.log(`ETA: ${progress.etaSeconds.toFixed(0)}s`);
  console.log(`Phase: ${progress.phase}`);
});
```

### With Dictionary Attack

```typescript
const cracker = new GroupTextCracker();

// Load wordlist from URL
await cracker.loadWordlist('/words_alpha.txt');

// Or set wordlist directly
cracker.setWordlist(['test', 'hello', 'world']);

const result = await cracker.crack(packetHex, { maxLength: 6 });
```

### Aborting and Resuming

```typescript
const cracker = new GroupTextCracker();

// Start cracking (in background)
const crackPromise = cracker.crack(packetHex, { maxLength: 8 }, (progress) => {
  // Abort after 10 seconds
  if (progress.elapsedSeconds > 10) {
    cracker.abort();
  }
});

const result = await crackPromise;

if (result.aborted && result.resumeFrom) {
  // Resume later from where we left off
  const resumed = await cracker.crack(packetHex, {
    maxLength: 8,
    startFrom: result.resumeFrom,
  });
}
```

## Utility Functions

For advanced usage, the library also exports utility functions:

```typescript
import {
  deriveKeyFromRoomName,  // Derive key from room name
  getChannelHash,         // Get channel hash from key
  verifyMac,              // Verify MAC
  isTimestampValid,       // Check timestamp validity
  isValidUtf8,            // Check UTF-8 validity
  indexToRoomName,        // Convert index to room name
  roomNameToIndex,        // Convert room name to index
  countNamesForLength,    // Count names for a length
  isWebGpuSupported,      // Check WebGPU support
  PUBLIC_ROOM_NAME,       // "[[public room]]"
  PUBLIC_KEY,             // Public room key
  DEFAULT_VALID_SECONDS,  // Default timestamp validity (30 days)
} from 'meshcore-cracker';
```
