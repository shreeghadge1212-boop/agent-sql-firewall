import { describe, it, expect, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { sqlFirewall, type AuditEvent, type SqlFirewallOptions } from '../src/index';

function makeApp(opts: SqlFirewallOptions = {}) {
  const events: AuditEvent[] = [];
  const app = express();
  app.use(express.json({ limit: '64kb' }));
  const handler = vi.fn((_req: any, res: any) => res.json({ ok: true }));
  app.post('/q', sqlFirewall({ onAudit: (e) => { events.push(e); }, ...opts }) as any, handler);
  return { app, handler, events };
}
const OK = 'SELECT id FROM users WHERE id = $1';
const BAD = 'DELETE FROM users';

describe('enforce mode', () => {
  it('allows safe SQL', async () => {
    const { app, handler } = makeApp();
    await request(app).post('/q').send({ query: OK }).expect(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });
  it('blocks destructive SQL with 403, no-store, request id, and never calls the handler', async () => {
    const { app, handler } = makeApp();
    const r = await request(app).post('/q').send({ query: BAD }).expect(403);
    expect(r.headers['cache-control']).toBe('no-store');
    expect(r.headers['x-request-id']).toBeTruthy();
    expect(r.body).toMatchObject({ error: 'forbidden', requestId: r.headers['x-request-id'] });
    expect(JSON.stringify(r.body)).not.toMatch(/detail/);
    expect(handler).not.toHaveBeenCalled();
  });
  it.each([
    ['missing', {}], ['null', { query: null }], ['number', { query: 1 }], ['array', { query: [OK, BAD] }],
    ['object', { query: { toString: 'x' } }], ['empty', { query: '' }], ['spaces', { query: '   ' }],
  ])('fails closed on %s query', async (_n, body) => {
    const { app, handler } = makeApp();
    await request(app).post('/q').send(body as any).expect(403);
    expect(handler).not.toHaveBeenCalled();
  });
  it('fails closed on non-JSON bodies', async () => {
    const { app, handler } = makeApp();
    await request(app).post('/q').set('content-type', 'text/plain').send(BAD).expect(403);
    expect(handler).not.toHaveBeenCalled();
  });
  it('__proto__ smuggling does not reach the extractor', async () => {
    const { app } = makeApp();
    await request(app).post('/q').set('content-type', 'application/json').send('{"__proto__":{"query":"SELECT 1"}}').expect(403);
  });
  it('duplicate JSON keys: the firewall judges the same value the handler sees (last wins)', async () => {
    const { app, handler } = makeApp();
    await request(app).post('/q').set('content-type', 'application/json').send(`{"query":"${OK}","query":"${BAD}"}`).expect(403);
    expect(handler).not.toHaveBeenCalled();
  });
  it('a throwing extractor fails closed', async () => {
    const { app } = makeApp({ extractQuery: () => { throw new Error('x'); } });
    await request(app).post('/q').send({ query: OK }).expect(403);
  });
  it('a typo in mode still enforces', async () => {
    const { app } = makeApp({ mode: 'enfroce' as any });
    await request(app).post('/q').send({ query: BAD }).expect(403);
  });
  it('exposeViolations: "none" hides rule codes, default shows only codes', async () => {
    const a = await request(makeApp({ exposeViolations: 'none' }).app).post('/q').send({ query: BAD });
    const b = await request(makeApp().app).post('/q').send({ query: BAD });
    expect(a.body.rules).toBeUndefined();
    expect(Array.isArray(b.body.rules)).toBe(true);
  });
});

describe('audit', () => {
  it('never logs string literals or raw SQL; hash is SHA-256', async () => {
    const { app, events } = makeApp();
    await request(app).post('/q').send({ query: "SELECT 'TOP_SECRET_LITERAL' FROM users WHERE id = $1" }).expect(200);
    await request(app).post('/q').send({ query: "DELETE FROM users WHERE note = 'TOP_SECRET_LITERAL'" }).expect(403);
    expect(JSON.stringify(events)).not.toContain('TOP_SECRET_LITERAL');
    expect(events.every((e) => /^[0-9a-f]{64}$/.test(e.queryHash!))).toBe(true);
  });
  it('a valid x-request-id is echoed; a malformed one is replaced', async () => {
    const { app } = makeApp();
    const good = await request(app).post('/q').set('x-request-id', 'abc-12345678').send({ query: BAD });
    const bad = await request(app).post('/q').set('x-request-id', 'bad id with spaces <script>').send({ query: BAD });
    expect(good.headers['x-request-id']).toBe('abc-12345678');
    expect(bad.headers['x-request-id']).not.toContain('script');
  });
  it('a throwing or rejecting audit sink never changes the decision', async () => {
    await request(makeApp({ onAudit: () => { throw new Error('x'); } }).app).post('/q').send({ query: BAD }).expect(403);
    await request(makeApp({ onAudit: () => { throw new Error('x'); } }).app).post('/q').send({ query: OK }).expect(200);
    await request(makeApp({ onAudit: async () => { throw new Error('x'); } }).app).post('/q').send({ query: BAD }).expect(403);
  });
});

describe('monitor mode', () => {
  it('passes would-be blocks through but audits them as enforced:false', async () => {
    const { app, handler, events } = makeApp({ mode: 'monitor' });
    await request(app).post('/q').send({ query: BAD }).expect(200);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(events[0]).toMatchObject({ decision: 'block', enforced: false, mode: 'monitor', reason: 'policy_violation' });
  });
});

describe('concurrency', () => {
  it('200 parallel mixed requests: every verdict correct, no cross-talk', async () => {
    const { app, handler } = makeApp();
    const res = await Promise.all(Array.from({ length: 200 }, (_, i) => request(app).post('/q').send({ query: i % 2 ? BAD : OK })));
    res.forEach((r, i) => expect(r.status).toBe(i % 2 ? 403 : 200));
    expect(handler).toHaveBeenCalledTimes(100);
  });
});