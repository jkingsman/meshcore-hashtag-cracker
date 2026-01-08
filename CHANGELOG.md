# Changelog

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
