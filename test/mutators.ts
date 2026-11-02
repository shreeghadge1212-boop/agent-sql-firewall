import fc from 'fast-check';

export function rng(seed: number) { // mulberry32, so every failure is reproducible
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
type R = () => number;
export type Mut = (sql: string, r: R) => string;

// splits SQL into [unquoted, quoted, unquoted, ...] so we never touch string literals
export const QUOTED = /('(?:[^']|'')*'|"(?:[^"]|"")*"|\$\$[\s\S]*?\$\$)/;
const PROTECTED = /('(?:[^']|'')*'|"(?:[^"]|"")*"|\$\$[\s\S]*?\$\$|--[^\n\r]*|\/\*[\s\S]*?\*\/)/;
const outside = (sql: string, f: (s: string) => string) =>
  sql.split(PROTECTED).map((s, i) => (i % 2 ? s : f(s))).join('');
const pick = <T,>(xs: T[], r: R): T => xs[Math.floor(r() * xs.length)];

const WS = [' ', '  ', '\t', '\n', '\r\n', '\f', ' /**/ ', ' /* x */ ', ' /* a /* nested */ b */ ', ' -- c\n ', '\n-- c\r\n'];

const caseMut: Mut = (s, r) => outside(s, (t) => [...t].map((c) => (r() < 0.5 ? c.toUpperCase() : c.toLowerCase())).join(''));
const wsMut: Mut = (s, r) => outside(s, (t) => t.replace(/ /g, () => pick(WS, r)));
const edgeMut: Mut = (s, r) => pick(['/* x */ ', '\n  ', '-- x\n'], r) + s + pick([' ;', ' ; -- x', '\n;;', ' /* end */'], r);

// Benign: meaning is unchanged, so a blocked attack must stay blocked and an allowed query must stay allowed.
export const MUTATORS: Record<string, Mut> = {
  case: caseMut,
  whitespace: wsMut,
  edges: edgeMut,
  combined: (s, r) => edgeMut(wsMut(caseMut(s, r), r), r),
};

// Hostile: may change meaning, so the ONLY rule is "attack must never become allowed".
export const HOSTILE: Record<string, Mut> = {
  unicodeSpace: (s) => outside(s, (t) => t.replace(/ /g, '\u00a0')),
  zeroWidth: (s) => outside(s, (t) => t.replace(/ /g, '\u200b ')),
  homoglyph: (s) => s.replace(/E/g, '\u0415').replace(/O/g, '\u041e'),
  fullwidth: (s) => outside(s, (t) => t.replace(/[A-Za-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0))),
};

// Grammar-based generator: produces lots of VALID write statements (bounded and unbounded mixed).
const COLS = ['id', 'user_id', 'name', 'tenant_id', 'role', 'total'];
const LITS = ['1', '2', '42', '-5', "'x'", '$1', '$2'];
const atom = fc
  .tuple(fc.constantFrom(...COLS), fc.constantFrom('=', '<>', '>', '<', '>=', 'LIKE', 'IN', 'IS NOT'), fc.constantFrom(...LITS))
  .map(([c, o, l]) => (o === 'IN' ? `${c} IN (${l}, ${l})` : o === 'IS NOT' ? `${c} IS NOT NULL` : `${c} ${o} ${l}`));
const cond = fc
  .array(fc.tuple(fc.constantFrom('AND', 'OR'), fc.boolean(), atom), { minLength: 1, maxLength: 4 })
  .map((parts) => parts.map(([op, neg, a], i) => `${i ? op + ' ' : ''}${neg ? `NOT (${a})` : a}`).join(' '));

export const statementArb = fc
  .tuple(fc.constantFrom('users', 'orders', 'sessions'), cond, fc.integer({ min: 0, max: 5 }))
  .map(([t, c, k]) => [
    `DELETE FROM ${t} WHERE ${c}`,
    `UPDATE ${t} SET user_id = 9 WHERE ${c}`,
    `SELECT * FROM ${t} WHERE ${c}`,
    `WITH x AS (DELETE FROM ${t} WHERE ${c} RETURNING id) SELECT * FROM x`,
    `DELETE FROM ${t} WHERE id = ${k} AND ${c}`,
    `UPDATE ${t} SET name = 'z' WHERE (${c}) OR id = ${k}`,
  ][k]);