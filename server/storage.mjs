import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { AccountEnforcement } from '../account-enforcement.mjs';

// One queue covers every connection operation, including async transaction
// callbacks. No unrelated request may accidentally join an open transaction.
export class PersistentStore {
  constructor(filename) {
    if (filename !== ':memory:') mkdirSync(dirname(filename), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(filename);
    if (filename !== ':memory:') chmodSync(filename, 0o600);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS entries (
        scope TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER,
        PRIMARY KEY (scope, key));`);
    this.pending = Promise.resolve();
    this.read = this.db.prepare('SELECT value, expires FROM entries WHERE scope=? AND key=?');
    this.write = this.db.prepare('INSERT INTO entries(scope,key,value,expires) VALUES(?,?,?,?) ON CONFLICT(scope,key) DO UPDATE SET value=excluded.value, expires=excluded.expires');
  }
  exclusive(fn) {
    const result = this.pending.then(fn);
    this.pending = result.catch(() => {});
    return result;
  }
  readValue(scope, key) {
    const row = this.read.get(scope, key);
    return row && (row.expires === null || row.expires > Date.now()) ? JSON.parse(row.value) : undefined;
  }
  storage(scope) {
    const direct = {
      get: async key => this.readValue(scope, key),
      put: async (key, value) => { this.write.run(scope, key, JSON.stringify(value), null); },
    };
    return {
      get: key => this.exclusive(() => direct.get(key)),
      put: (key, value) => this.exclusive(() => direct.put(key, value)),
      transaction: fn => this.exclusive(async () => {
        this.db.exec('BEGIN IMMEDIATE');
        try { const result = await fn(direct); this.db.exec('COMMIT'); return result; }
        catch (error) { this.db.exec('ROLLBACK'); throw error; }
      }),
    };
  }
  get kv() {
    return {
      get: key => this.exclusive(() => this.readValue('kv', key) ?? null),
      put: (key, value, options = {}) => this.exclusive(() => {
        const expiry = options.expirationTtl ? Date.now() + options.expirationTtl * 1000 : options.expiration ? options.expiration * 1000 : null;
        this.write.run('kv', key, JSON.stringify(String(value)), expiry);
      }),
    };
  }
  get enforcement() {
    return {
      idFromName: identity => identity,
      get: identity => new AccountEnforcement({ storage: this.storage('identity:' + identity) }),
    };
  }
  close() { this.db.close(); }
}
