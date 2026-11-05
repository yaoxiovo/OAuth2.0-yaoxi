import { readFileSync } from 'node:fs';
import { PersistentStore } from './storage.mjs';

const [snapshotPath, dbPath] = process.argv.slice(2);
if (!snapshotPath || !dbPath) throw new Error('Usage: node server/import.mjs snapshot.json database.sqlite');
const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8'));
const db = new PersistentStore(dbPath);
if (await db.kv.get('sso_global_config')) throw new Error('Refusing to overwrite an initialized database');
await db.exclusive(() => {
  db.db.exec('BEGIN IMMEDIATE');
  try {
    for (const entry of snapshot.kv) db.write.run('kv', entry.name, JSON.stringify(entry.value), entry.expiration ? entry.expiration * 1000 : null);
    for (const object of snapshot.identities) {
      for (const [key, value] of object.entries) db.write.run('identity:' + object.identity, key, JSON.stringify(value), null);
    }
    db.db.exec('COMMIT');
  } catch (error) { db.db.exec('ROLLBACK'); throw error; }
});
console.log(JSON.stringify({ importedKeys: snapshot.kv.length, importedIdentities: snapshot.identities.length }));
db.close();
