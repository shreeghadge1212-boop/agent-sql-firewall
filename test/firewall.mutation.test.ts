import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { createFirewall } from '../src/astFirewall';
import { ATTACK_LIST, LEGIT } from './corpus';
import { MUTATORS, HOSTILE, rng } from './mutators';

const fw = createFirewall();
const attacks = ATTACK_LIST.map((a) => a.sql);

describe('an attack never becomes allowed under ANY mutation', () => {
  for (const [name, mut] of Object.entries({ ...MUTATORS, ...HOSTILE })) {
    it(name, () => {
      fc.assert(
        fc.property(fc.constantFrom(...attacks), fc.integer(), (sql, seed) => {
          const m = mut(sql, rng(seed));
          if (fw.evaluate(m).decision !== 'block') throw new Error('BYPASS: ' + JSON.stringify(m));
          return true;
        }),
        { numRuns: 4000 },
      );
    });
  }
});

describe('a legit query stays allowed under benign mutations (normalization consistency)', () => {
  for (const [name, mut] of Object.entries(MUTATORS)) {
    it(name, () => {
      fc.assert(
        fc.property(fc.constantFrom(...LEGIT), fc.integer(), (sql, seed) => {
          const m = mut(sql, rng(seed));
          const v = fw.evaluate(m);
          if (v.decision !== 'allow') throw new Error('FALSE POSITIVE: ' + JSON.stringify(m) + ' -> ' + v.violations.map((x) => x.rule));
          return true;
        }),
        { numRuns: 2000 },
      );
    });
  }
});