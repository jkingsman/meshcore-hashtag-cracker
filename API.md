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

#### `decodePacket(packetHex: string): Promise<DecodedPacket | null>`

Decode a packet and extract the information needed for cracking. Returns `null` if the packet is invalid or not a GroupText packet.

**Parameters:**
- `packetHex: string` - The packet data as a hex string

**Returns:** `Promise<DecodedPacket | null>`

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
  startFromType?: 'dictionary' | 'bruteforce'; // Type of resume position (default: 'bruteforce')
  forceCpu?: boolean;           // Force CPU-based cracking (default: false)
  gpuDispatchMs?: number;       // EXPERIMENTAL: GPU dispatch target time (default: 1000)
}
```

#### gpuDispatchMs (Experimental)

Target time in milliseconds for each GPU dispatch batch. The cracker auto-tunes batch sizes to hit this target. Higher values improve throughput but reduce responsiveness.

**Risks of high values (>2000ms):**
- Browser watchdog timeouts or "device lost" errors
- System UI stuttering during dispatches
- Delayed response to `abort()` calls
- Progress updates less frequent

Values up to ~10000ms may work on modern GPUs (tested on RTX 4080 Super), but stability varies by browser, OS, and hardware. Test thoroughly on your target environment.

### CrackResult

```typescript
interface CrackResult {
  found: boolean;
  roomName?: string;          // Room name without '#'
  key?: string;               // Encryption key (hex)
  decryptedMessage?: string;  // Decrypted message
  aborted?: boolean;          // Was operation aborted
  resumeFrom?: string;        // Position for resume (always set on success/abort/not-found)
  resumeType?: 'dictionary' | 'bruteforce'; // Type of resume position
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

### DecodedPacket

```typescript
interface DecodedPacket {
  channelHash: string;   // Channel hash (1 byte, hex)
  ciphertext: string;    // Encrypted ciphertext (hex)
  cipherMac: string;     // MAC for verification (2 bytes, hex)
  isGroupText: boolean;  // Whether this is a GroupText packet
}
```

## Validation Filters

The cracker uses two filters to quickly reject false positives and improve accuracy:

### Timestamp Filter

`useTimestampFilter` (default: `true`)

MeshCore packets contain a timestamp field. When a candidate key decrypts the packet, the timestamp filter checks whether the resulting timestamp falls within the validity window. If the decrypted timestamp is far in the past or future, it indicates the wrong key was used but had a MAC collision, and the candidate is rejected. This dramatically reduces false positives since random decryption rarely produces a plausible recent timestamp.

The validity window can be customized using the `validSeconds` option (default: 2592000 seconds = 30 days). For example, to only accept packets from the last hour:

```typescript
const result = await cracker.crack(packetHex, {
  useTimestampFilter: true,
  validSeconds: 3600, // 1 hour
});
```

### UTF-8 Filter

`useUtf8Filter` (default: `true`)

When decrypting with an incorrect key, the MAC can collide and the resulting bytes are essentially random and often form invalid UTF-8 sequences. The UTF-8 filter checks whether the decrypted message contains the Unicode replacement character (`U+FFFD`), which appears when bytes cannot be decoded as valid UTF-8. Messages containing this character are rejected as false positives.

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

CPU mode is useful for environments without WebGPU (i.e. Node.js or older browsers).

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

The cracker tracks where it stopped and provides resume information:

```typescript
const cracker = new GroupTextCracker();
await cracker.loadWordlist('/words.txt');

// Start cracking (in background)
const crackPromise = cracker.crack(packetHex, { maxLength: 8 }, (progress) => {
  // Abort after 10 seconds
  if (progress.elapsedSeconds > 10) {
    cracker.abort();
  }
});

const result = await crackPromise;

if (result.aborted && result.resumeFrom) {
  // Resume from where we left off, preserving the phase (dictionary or brute force)
  const resumed = await cracker.crack(packetHex, {
    maxLength: 8,
    startFrom: result.resumeFrom,
    startFromType: result.resumeType, // 'dictionary' or 'bruteforce'
  });
}
```

**Resume behavior:**

- `startFromType: 'dictionary'` - Resume from AFTER a dictionary word, then continue to brute force after dictionary completes
- `startFromType: 'bruteforce'` (default) - Skip dictionary entirely, resume brute force from AFTER the specified position

Both resume types skip past the given position, making it easy to find additional matches.

### Skipping False Positives

When a match is found, `resumeFrom` and `resumeType` are always provided. This allows you to skip past false positives (MAC collisions, etc.) and continue searching:

```typescript
const result = await cracker.crack(packetHex, { maxLength: 8 });

if (result.found) {
  // Check if this is actually the room we want...
  if (isFalsePositive(result)) {
    // Skip this result and continue searching
    const nextResult = await cracker.crack(packetHex, {
      maxLength: 8,
      startFrom: result.resumeFrom,
      startFromType: result.resumeType,
    });
  }
}
```

**Important:** The dictionary and brute force phases are independent. A room name found in the dictionary (e.g., "able") will be encountered again during brute force. If you have false positives to skip again in the bruteforce, you'll need to track them yourself and automate the continuation when one is found again.

## Built-in Wordlist

The library includes a built-in English wordlist for dictionary attacks, available as a separate entry point:

```typescript
import { ENGLISH_WORDLIST } from 'meshcore-hashtag-cracker/wordlist';

cracker.setWordlist(ENGLISH_WORDLIST);
```

- **370,105 words** - Filtered to valid room name format (a-z, 0-9, dashes)
- **Tree-shakeable** - Only included in your bundle if you import it
- **~4MB** - Consider lazy-loading for browser apps if bundle size is a concern

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
} from 'meshcore-hashtag-cracker';
```
