import { describe, expect, it } from 'vitest';
import { randomInt, randomString } from './random';

describe('randomString', () => {
  it('returns 22 characters from the alphanumeric alphabet', () => {
    for (let i = 0; i < 100; i++) {
      expect(randomString()).toMatch(/^[A-Za-z0-9]{22}$/);
    }
  });

  it('returns different values on each call', () => {
    expect(randomString()).not.toBe(randomString());
  });
});

describe('randomInt', () => {
  it('stays within [min, max)', () => {
    for (let i = 0; i < 1000; i++) {
      const n = randomInt(0, 62);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(62);
    }
  });

  it('eventually produces values across the whole range', () => {
    const seen = new Set<number>();
    for (let i = 0; i < 2000; i++) {
      seen.add(randomInt(0, 10));
    }
    expect(seen.size).toBe(10);
  });
});
