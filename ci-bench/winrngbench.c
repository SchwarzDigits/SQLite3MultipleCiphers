/*
** Windows: cost of the random sources SQLite3 Multiple Ciphers can use, and
** of a write-heavy workload, with and without SQLITE3MC_USE_OS_RNG.
**
** Built three times by the workflow:
**   A: SQLITE3MC_USE_RAND_S=1, SQLITE3MC_USE_OS_RNG=0 (today's default)
**   B: SQLITE3MC_USE_RAND_S=1, SQLITE3MC_USE_OS_RNG=1
**   C: SQLITE3MC_USE_RAND_S=0, SQLITE3MC_USE_OS_RNG=1 (RtlGenRandom)
*/
#include "sqlite3mc.c"
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif

static double now(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double) c.QuadPart / (double) f.QuadPart;
}

typedef void (*RandomSource)(unsigned char*, size_t);

static void fromEntropy(unsigned char* b, size_t n) { if (entropy(b, n) != n) abort(); }
static void fromBcrypt(unsigned char* b, size_t n)
{
  if (BCryptGenRandom(NULL, b, (ULONG) n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
}
static void fromRng(unsigned char* b, size_t n) { chacha20_rng(b, n); }

static void benchSource(const char* name, RandomSource f)
{
  static const size_t sizes[] = { 12, 16, 32, 128 };
  unsigned char buf[128];
  size_t s;
  for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
  {
    const int iters = 100000;
    double best = 1e9;
    int run, i;
    for (run = 0; run < 5; run++)
    {
      double t0 = now();
      for (i = 0; i < iters; i++) f(buf, sizes[s]);
      { double t = (now() - t0) / iters * 1e9; if (t < best) best = t; }
    }
    printf("  %-40s %4u B  %8.1f ns\n", name, (unsigned) sizes[s], best);
  }
}

static int exec(sqlite3* db, const char* sql)
{
  char* err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  if (rc != SQLITE_OK) { printf("  error in %s: %s\n", sql, err); sqlite3_free(err); }
  return rc;
}

/* Microseconds per small write transaction (one row updated, WAL, synchronous=OFF) */
static double benchDatabase(const char* cipher, int* ok)
{
  char path[MAX_PATH + 64], uri[MAX_PATH + 160];
  sqlite3* db;
  sqlite3_stmt* st;
  double t0, t1;
  int i;
  const int transactions = 20000;
  GetTempPathA(MAX_PATH, path);
  strcat(path, "winrngbench.db");
  DeleteFileA(path);
  { char wal[MAX_PATH + 70]; sprintf(wal, "%s-wal", path); DeleteFileA(wal); }
  sprintf(uri, "file:%s?cipher=%s%s", path, cipher, strcmp(cipher, "sqlcipher") == 0 ? "&legacy=4" : "");
  if (sqlite3_open_v2(uri, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL) != SQLITE_OK) { *ok = 0; return 0; }
  sqlite3_key(db, "secret", 6);
  exec(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF;");
  exec(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, v BLOB);"
           "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<2000) "
           "INSERT INTO t SELECT i, randomblob(100) FROM c;");
  sqlite3_prepare_v2(db, "UPDATE t SET v = randomblob(100) WHERE id = ?", -1, &st, NULL);
  t0 = now();
  for (i = 0; i < transactions; i++)
  {
    sqlite3_bind_int(st, 1, 1 + (i * 7919) % 2000);
    sqlite3_step(st);
    sqlite3_reset(st);
  }
  t1 = now();
  sqlite3_finalize(st);
  sqlite3_close(db);
  /* Reopen and check that everything is readable */
  sqlite3_open_v2(uri, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_URI, NULL);
  sqlite3_key(db, "secret", 6);
  {
    int rows = -1;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM t", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
      rows = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    *ok = (rows == 2000) && exec(db, "PRAGMA quick_check") == SQLITE_OK;
  }
  sqlite3_close(db);
  DeleteFileA(path);
  return (t1 - t0) / transactions * 1e6;
}

int main(void)
{
  static const char* ciphers[] = { "sqlcipher", "chacha20" };
  int c, allOk = 1;
  printf("build: SQLITE3MC_USE_RAND_S=%d, SQLITE3MC_USE_OS_RNG=%d\n", SQLITE3MC_USE_RAND_S, SQLITE3MC_USE_OS_RNG);
  printf("random sources (best of 5 x 100000 calls):\n");
  benchSource(SQLITE3MC_USE_RAND_S ? "entropy() via rand_s" : "entropy() via RtlGenRandom", fromEntropy);
  benchSource("BCryptGenRandom (system preferred RNG)", fromBcrypt);
  benchSource(SQLITE3MC_USE_OS_RNG ? "chacha20_rng (direct from the OS)" : "chacha20_rng (ChaCha20 generator)", fromRng);
  printf("database, one-row write transactions (WAL, synchronous=OFF), best of 3:\n");
  for (c = 0; c < 2; c++)
  {
    double best = 1e9;
    int run, ok = 1;
    for (run = 0; run < 3; run++)
    {
      int okRun = 0;
      double t = benchDatabase(ciphers[c], &okRun);
      ok = ok && okRun;
      if (t < best) best = t;
    }
    printf("  %-10s %8.2f us per transaction  %s\n", ciphers[c], best, ok ? "(reopened ok)" : "(FAILED)");
    allOk = allOk && ok;
  }
  return allOk ? 0 : 1;
}
