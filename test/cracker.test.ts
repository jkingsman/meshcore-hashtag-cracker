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
