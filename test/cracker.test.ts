import { describe, it, expect } from 'vitest';
import { GroupTextCracker } from '../src/cracker';
import {
  deriveKeyFromRoomName,
  getChannelHash,
  verifyMac,
  indexToRoomName,
  roomNameToIndex,
  countNamesForLength,
} from '../src/core';

describe('Core Functions', () => {
  describe('deriveKeyFromRoomName', () => {
    it('should derive key from room name #aa', () => {
      const key = deriveKeyFromRoomName('#aa');
      // SHA256("#aa") first 16 bytes
      expect(key).toHaveLength(32); // 16 bytes = 32 hex chars
    });

    it('should derive consistent keys', () => {
      const key1 = deriveKeyFromRoomName('#test');
      const key2 = deriveKeyFromRoomName('#test');
      expect(key1).toBe(key2);
    });
  });

  describe('getChannelHash', () => {
    it('should compute channel hash from key', () => {
      const key = deriveKeyFromRoomName('#aa');
      const hash = getChannelHash(key);
      expect(hash).toHaveLength(2); // 1 byte = 2 hex chars
    });
  });

  describe('indexToRoomName / roomNameToIndex', () => {
    it('should convert index 0 length 1 to "a"', () => {
      expect(indexToRoomName(1, 0)).toBe('a');
    });

    it('should convert index 1 length 1 to "b"', () => {
      expect(indexToRoomName(1, 1)).toBe('b');
    });

    it('should convert "aa" to index', () => {
      const result = roomNameToIndex('aa');
      expect(result).not.toBeNull();
      expect(result!.length).toBe(2);
    });

    it('should roundtrip room names', () => {
      const testNames = ['a', 'z', 'aa', 'test', 'ab-cd', '123'];
      for (const name of testNames) {
        const idx = roomNameToIndex(name);
        expect(idx).not.toBeNull();
        const recovered = indexToRoomName(idx!.length, idx!.index);
        expect(recovered).toBe(name);
      }
    });
  });

  describe('countNamesForLength', () => {
    it('should count 36 names for length 1', () => {
      expect(countNamesForLength(1)).toBe(36);
    });

    it('should count 36*36 names for length 2', () => {
      expect(countNamesForLength(2)).toBe(36 * 36);
    });
  });
});

describe('GroupTextCracker', () => {
  // Test packet: room #aa, message "foo"
  const testPacket = '150013752F15A1BF3C018EB1FC4F26B5FAEB417BB0F1AE8FF07655484EBAA05CB9A927D689';

  describe('crack with CPU fallback', () => {
    it('should crack #aa room with message "foo"', async () => {
      const cracker = new GroupTextCracker();

      const result = await cracker.crack(testPacket, {
        forceCpu: true,
        maxLength: 2,
        useTimestampFilter: false, // Disable for test - packet timestamp may be old
        useUtf8Filter: true,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('aa');
      expect(result.decryptedMessage).toBe('foo');
      expect(result.key).toBeDefined();

      cracker.destroy();
    });

    it('should respect startingLength option', async () => {
      const cracker = new GroupTextCracker();

      // Start at length 2, should still find 'aa'
      const result = await cracker.crack(testPacket, {
        forceCpu: true,
        maxLength: 2,
        startingLength: 2,
        useTimestampFilter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('aa');

      cracker.destroy();
    });

    it('should not find result when startingLength is too high', async () => {
      const cracker = new GroupTextCracker();

      // Start at length 3, should not find 'aa' (length 2)
      const result = await cracker.crack(testPacket, {
        forceCpu: true,
        maxLength: 3,
        startingLength: 3,
        useTimestampFilter: false,
      });

      expect(result.found).toBe(false);

      cracker.destroy();
    });

    it('should skip dictionary attack when useDictionary is false', async () => {
      const cracker = new GroupTextCracker();

      // Load a wordlist that includes 'aa'
      cracker.setWordlist(['aa', 'bb', 'test']);

      // Disable dictionary, should still find via brute force
      const result = await cracker.crack(testPacket, {
        forceCpu: true,
        maxLength: 2,
        useDictionary: false,
        useTimestampFilter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('aa');

      cracker.destroy();
    });

    it('should use dictionary attack when enabled', async () => {
      const cracker = new GroupTextCracker();

      // Load a wordlist that includes 'aa'
      cracker.setWordlist(['aa', 'bb', 'test']);

      const result = await cracker.crack(testPacket, {
        forceCpu: true,
        maxLength: 2,
        useDictionary: true,
        useTimestampFilter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('aa');

      cracker.destroy();
    });
  });

  describe('resume functionality', () => {
    // Test packet with multiple collisions (filters disabled):
    // First match: #able (dictionary or brute force)
    // Second match: #q81eb (brute force only)
    const multiMatchPacket = '15002b77ca26cf0d63aacc998f893262ef923f71033c0cbc2de92b5189d13d45dd39141ae3';

    it('should find first match (#able) in dictionary', async () => {
      const cracker = new GroupTextCracker();
      cracker.setWordlist(['aardvark', 'able', 'about', 'q81eb', 'zebra']);

      const result = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('able');

      cracker.destroy();
    });

    it('should find second match (#q81eb) when resuming from dictionary after #able', async () => {
      const cracker = new GroupTextCracker();
      // 'able' is before 'q81eb' in this wordlist
      cracker.setWordlist(['aardvark', 'able', 'about', 'q81eb', 'zebra']);

      // Resume from 'about' (after 'able') - should find 'q81eb' next in dictionary
      const result = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        startFrom: 'about',
        startFromType: 'dictionary',
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('q81eb');

      cracker.destroy();
    });

    it('should find first match (#able) in brute force when no dictionary', async () => {
      const cracker = new GroupTextCracker();

      const result = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        useDictionary: false,
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('able');
      // resumeFrom/resumeType now always provided on success for skipping false positives
      expect(result.resumeFrom).toBe('able');
      expect(result.resumeType).toBe('bruteforce');

      cracker.destroy();
    });

    // NOTE: This test performs actual CPU brute-force cracking to find a 5-character
    // room name collision. On slower hardware, this may take 30-60+ seconds.
    // If this test times out, your CPU may simply be slower than expected - the
    // library is still working correctly.
    it('should find second match (#q81eb) when resuming brute force after #able', async () => {
      const cracker = new GroupTextCracker();

      // Resume from 'able' in brute force - should skip 'able' and find 'q81eb'
      const result = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        startFrom: 'able',
        startFromType: 'bruteforce',
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('q81eb');

      cracker.destroy();
    }, 120000);

    it('should return resumeType: dictionary when match found during dictionary phase', async () => {
      const cracker = new GroupTextCracker();
      cracker.setWordlist(['able', 'q81eb']);

      // Find 'able', then verify we can resume to find 'q81eb'
      const firstResult = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(firstResult.found).toBe(true);
      expect(firstResult.roomName).toBe('able');

      // Now resume from 'able' using dictionary type - should find 'q81eb'
      const secondResult = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        startFrom: 'able',
        startFromType: 'dictionary',
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(secondResult.found).toBe(true);
      expect(secondResult.roomName).toBe('q81eb');

      cracker.destroy();
    });

    it('should skip dictionary entirely when resuming with bruteforce type', async () => {
      const cracker = new GroupTextCracker();
      // Put 'able' in dictionary - but brute force resume should skip dictionary
      cracker.setWordlist(['able']);

      // Resume from brute force position before 'able' but with bruteforce type
      // Should find 'able' via brute force, not dictionary
      const result = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        startFrom: 'a', // Before 'able' in brute force order
        startFromType: 'bruteforce',
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('able');

      cracker.destroy();
    });

    // NOTE: This test performs actual CPU brute-force cracking to find a 5-character
    // room name collision. On slower hardware, this may take 30-60+ seconds.
    // If this test times out, your CPU may simply be slower than expected - the
    // library is still working correctly.
    it('should not find #able when resuming brute force from after it', async () => {
      const cracker = new GroupTextCracker();

      // Resume from 'ablf' (just after 'able') - should miss 'able' but find 'q81eb'
      const result = await cracker.crack(multiMatchPacket, {
        forceCpu: true,
        maxLength: 5,
        startFrom: 'ablf',
        startFromType: 'bruteforce',
        useTimestampFilter: false,
        useUtf8Filter: false,
      });

      expect(result.found).toBe(true);
      expect(result.roomName).toBe('q81eb');

      cracker.destroy();
    }, 120000);
  });

  describe('decodePacket', () => {
    it('should decode valid GroupText packet', async () => {
      const cracker = new GroupTextCracker();
      const decoded = await cracker.decodePacket(testPacket);

      expect(decoded).not.toBeNull();
      expect(decoded!.isGroupText).toBe(true);
      expect(decoded!.channelHash).toBeDefined();
      expect(decoded!.ciphertext).toBeDefined();
      expect(decoded!.cipherMac).toBeDefined();

      cracker.destroy();
    });

    it('should return null for invalid packet', async () => {
      const cracker = new GroupTextCracker();
      const decoded = await cracker.decodePacket('invalid');

      expect(decoded).toBeNull();

      cracker.destroy();
    });
  });
});
