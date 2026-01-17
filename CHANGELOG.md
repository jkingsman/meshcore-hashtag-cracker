# Changelog

## v1.6.0

**Features:**
- Added `useSenderFilter` option (default: `true`) to filter results by sender presence
  - Rejects decrypted messages that don't have a valid sender field
  - When a sender is found, `decryptedMessage` returns "sender: message" format
  - More effective than timestamp filter for rejecting MAC collisions
- GPU performance optimization: increased `CANDIDATES_PER_THREAD` from 16 to 32

**Wordlist:**
- Expanded wordlist to include US airport codes and USA county/town names

**Documentation:**
- Updated all documentation to reflect new filter options and defaults
- Added new test packets with sender field examples

## v1.5.0

**Wordlist:**
- Expanded English wordlist with additional geographic terms

## v1.4.0

**Features:**
- Added `gpuDispatchMs` option (experimental) for tuning GPU dispatch batch timing
  - Default: 1000ms, tested up to 10000ms on high-end GPUs
  - Higher values improve throughput but reduce responsiveness
- Added `decodePacket()` method to extract packet info without cracking

**Documentation:**
- Documented `decodePacket()` method and `DecodedPacket` type in API.md
- Fixed incorrect import path in API.md (`meshcore-cracker` → `meshcore-hashtag-cracker`)

## v1.3.0

**Features:**
- Built-in English wordlist (370k words) available as separate tree-shakeable entry point
  ```typescript
  import { ENGLISH_WORDLIST } from 'meshcore-hashtag-cracker/wordlist';
  ```
- Dictionary attack runs before GPU brute force for faster cracking of common room names

**Bug fixes:**
- Packet hex is now case-insensitive (lowercase, uppercase, and mixed case all work)

**Documentation:**
- Unified README examples with wordlist usage and explanatory comments
- Added dictionary attack tests

## v1.2.1

**Documentation:**
- Added `startFromType` to README options example
- Added multi-collision test packet to CLAUDE.md
- Documented "startFrom is exclusive" behavior in gotchas

## v1.2.0

**Bug fixes:**
- `resumeFrom`/`resumeType` now set on successful matches, enabling "skip false positive" workflows
- `startFrom` now means "start AFTER" (exclusive) instead of "start AT" (inclusive)
- Progress calculation now correctly reflects remaining search space when resuming
- `startFrom` is now case-insensitive

## v1.1.0

**Features:**
- Added resume support: `startFrom`/`startFromType` options and `resumeFrom`/`resumeType` in results
- Added `validSeconds` option to customize timestamp filter window
