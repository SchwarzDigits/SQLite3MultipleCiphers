/*
** Check of SQLITE3MC_USE_OS_RNG on a platform (test branch only, not part of the PR).
**
** 1. chacha20_rng: outputs of every size callers use (and more) differ and look random.
** 2. Every cipher: create a file database, write, sort through a temporary file,
**    reopen, check content and integrity; two databases with the same passphrase
**    must get different salts; no plaintext marker in the file.
**
** Prints "osrngcheck: N checks, M failures" and exits with 1 on failure.
*/
#include "sqlite3mc.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !SQLITE3MC_USE_OS_RNG && !defined(OSRNG_ALLOW_OFF)
#error "build with -DSQLITE3MC_USE_OS_RNG=1"
#endif

static int nChecks = 0, nFails = 0;
#define CHECK(cond, ...) do { nChecks++; if (!(cond)) { nFails++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int popcount(const unsigned char* p, size_t n)
{
  int c = 0; size_t i;
  for (i = 0; i < n; i++) { unsigned v = p[i]; while (v) { c += v & 1; v >>= 1; } }
  return c;
}

static void testRng(void)
{
  static unsigned char a[4096], b[4096];
  static const size_t sizes[] = { 8, 12, 16, 24, 32, 48, 64, 128, 255, 256
#if !defined(SQLITE3MC_WASM_USE_GETENTROPY)
    , 257, 1000, 4096
#endif
  };
  size_t k; int i, same = 0;
  for (k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
    size_t n = sizes[k];
    chacha20_rng(a, n);
    chacha20_rng(b, n);
    CHECK(memcmp(a, b, n) != 0, "rng: two outputs of %d bytes are equal", (int) n);
    if (n >= 64) {
      int bits = popcount(a, n), total = (int) n * 8;
      CHECK(bits > total * 4 / 10 && bits < total * 6 / 10, "rng: %d of %d bits set for %d bytes", bits, total, (int) n);
    }
  }
  /* Many short requests, as for nonces: no output may repeat the previous one */
  chacha20_rng(a, 16);
  for (i = 0; i < 100000; i++) {
    chacha20_rng(b, 16);
    if (memcmp(a, b, 16) == 0) same++;
    memcpy(a, b, 16);
  }
  CHECK(same == 0, "rng: %d repeated 16-byte outputs", same);
}

static int exec(sqlite3* db, const char* sql, const char* what)
{
  char* err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  CHECK(rc == SQLITE_OK, "%s: rc=%d %s", what, rc, err ? err : "");
  sqlite3_free(err);
  return rc;
}

static char* query(sqlite3* db, const char* sql)
{
  sqlite3_stmt* st; char* r;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return sqlite3_mprintf("error: %s", sqlite3_errmsg(db));
  r = sqlite3_step(st) == SQLITE_ROW ? sqlite3_mprintf("%s", (const char*) sqlite3_column_text(st, 0))
                                     : sqlite3_mprintf("error: %s", sqlite3_errmsg(db));
  sqlite3_finalize(st);
  return r;
}

static int readFile(const char* path, unsigned char** pBuf, long* pLen)
{
  FILE* f = fopen(path, "rb"); long n;
  if (!f) return 0;
  fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
  *pBuf = malloc(n > 0 ? n : 1);
  *pLen = (long) fread(*pBuf, 1, n, f);
  fclose(f);
  return 1;
}

static int contains(const unsigned char* buf, long n, const char* marker)
{
  long m = (long) strlen(marker), i;
  for (i = 0; i + m <= n; i++) if (memcmp(buf + i, marker, m) == 0) return 1;
  return 0;
}

typedef struct { const char* name; const char* setup; } Cfg;
static const Cfg CFGS[] = {
  { "chacha20",     "PRAGMA cipher='chacha20'; PRAGMA key='pass';" },
  { "sqlcipher",    "PRAGMA cipher='sqlcipher'; PRAGMA legacy=4; PRAGMA key='pass';" },
  { "aegis",        "PRAGMA cipher='aegis'; PRAGMA key='pass';" },
  { "ascon128",     "PRAGMA cipher='ascon128'; PRAGMA key='pass';" },
  { "aes128cbc",    "PRAGMA cipher='aes128cbc'; PRAGMA key='pass';" },
  { "aes256cbc",    "PRAGMA cipher='aes256cbc'; PRAGMA key='pass';" },
  { "chacha20-wal", "PRAGMA cipher='chacha20'; PRAGMA key='pass'; PRAGMA journal_mode=WAL;" },
  { "sqlcipher-wal","PRAGMA cipher='sqlcipher'; PRAGMA legacy=4; PRAGMA key='pass'; PRAGMA journal_mode=WAL;" },
};

static const char* FILL =
  "CREATE TABLE t(i INTEGER PRIMARY KEY, v TEXT);"
  "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<3000)"
  " INSERT INTO t SELECT i, 'PLAINTEXT-MARKER-' || printf('%0400d', i) FROM c;";

static void testCipher(const Cfg* c)
{
  char path[2][64];
  unsigned char* buf[2] = { NULL, NULL }; long len[2] = { 0, 0 };
  int k;
  for (k = 0; k < 2; k++) {
    sqlite3* db = NULL; char* r;
    snprintf(path[k], sizeof path[k], "osrng-%s-%d.db", c->name, k);
    remove(path[k]);
    if (sqlite3_open(path[k], &db) != SQLITE_OK) { CHECK(0, "%s: open", c->name); sqlite3_close(db); return; }
    if (exec(db, c->setup, c->name) != SQLITE_OK || exec(db, FILL, c->name) != SQLITE_OK) { sqlite3_close(db); return; }
    /* A sort that does not fit into memory goes through an encrypted temporary file */
    exec(db, "PRAGMA temp_store=FILE; PRAGMA cache_size=10; CREATE TABLE s AS SELECT * FROM t ORDER BY v DESC;", c->name);
    sqlite3_close(db);

    db = NULL;
    sqlite3_open(path[k], &db);
    exec(db, c->setup, c->name);
    r = query(db, "SELECT count(*) || ':' || sum(length(v)) FROM s");
    CHECK(strcmp(r, "3000:1251000") == 0, "%s: content %s", c->name, r);
    sqlite3_free(r);
    r = query(db, "PRAGMA integrity_check");
    CHECK(strcmp(r, "ok") == 0, "%s: integrity %s", c->name, r);
    sqlite3_free(r);
    sqlite3_close(db);

    if (readFile(path[k], &buf[k], &len[k]))
      CHECK(!contains(buf[k], len[k], "PLAINTEXT-MARKER"), "%s: plaintext in the file", c->name);
  }
  /* Same passphrase, same content: the files must differ from the first byte on
     (salt) or at least in the page data (IVs, nonces) */
  if (buf[0] && buf[1]) {
    CHECK(len[0] == len[1] && len[0] > 0, "%s: file sizes %ld and %ld", c->name, len[0], len[1]);
    if (strncmp(c->name, "aes", 3) == 0)
      CHECK(1, "");  /* aes128cbc/aes256cbc are deterministic: no salt, no random IV */
    else
      CHECK(memcmp(buf[0], buf[1], 16) != 0, "%s: both files have the same salt", c->name);
  }
  free(buf[0]); free(buf[1]);
  for (k = 0; k < 2; k++) {
    char tmp[80];
    remove(path[k]);
    snprintf(tmp, sizeof tmp, "%s-wal", path[k]); remove(tmp);
    snprintf(tmp, sizeof tmp, "%s-shm", path[k]); remove(tmp);
  }
  printf("ok %s\n", c->name);
}

int main(void)
{
  size_t i;
  printf("sqlite3mc %s, SQLITE3MC_USE_OS_RNG=%d\n", sqlite3mc_version(), SQLITE3MC_USE_OS_RNG);
  testRng();
  printf("ok rng\n");
  for (i = 0; i < sizeof CFGS / sizeof CFGS[0]; i++) testCipher(&CFGS[i]);
  printf("osrngcheck: %d checks, %d failures\n", nChecks, nFails);
  return nFails != 0;
}
