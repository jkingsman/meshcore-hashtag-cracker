# Changelog

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
