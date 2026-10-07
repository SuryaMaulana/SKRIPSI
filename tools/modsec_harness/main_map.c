#include "tfns_body_map.c"
static void load_map(const char *path, unsigned cp) {          /* port of unicode_map_init (msc_unicode.c) */
  FILE *f = fopen(path, "rb"); fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  char *buf = malloc(n + 1); fread(buf, 1, n, f); buf[n] = 0; fclose(f);
  unicode_codepage = cp; unicode_map_table = malloc(sizeof(int) * 65536); memset(unicode_map_table, -1, sizeof(int) * 65536);
  unicode_map_table[0x3002] = 0x2e; unicode_map_table[0xff61] = 0x2e; unicode_map_table[0xff0e] = 0x2e; unicode_map_table[0x002e] = 0x2e;
  int found = 0, processing = 0; char *save = NULL;
  for (char *p = strtok_r(buf, " \t\n\r", &save); p; p = strtok_r(NULL, " \t\n\r", &save)) {
    if ((unsigned)atol(p) == cp) found = 1;
    if (found && strchr(p, ':')) { unsigned code = 0, map = 0; processing = 1; sscanf(p, "%x:%x", &code, &map); if (code <= 65535) unicode_map_table[code] = map; }
    if (processing && !strchr(p, ':')) break;
  }
}
typedef int (*tfn_t)(apr_pool_t *, unsigned char *, long int, char **, long int *);
static struct { const char *name; tfn_t fn; } TF[] = {
  {"cmdLine", msre_fn_cmdline_execute}, {"lowercase", msre_fn_lowercase_execute},
  {"removeNulls", msre_fn_removeNulls_execute}, {"compressWhitespace", msre_fn_compressWhitespace_execute},
  {"cssDecode", msre_fn_cssDecode_execute}, {"removeWhitespace", msre_fn_removeWhitespace_execute},
  {"removeCommentsChar", msre_fn_removeCommentsChar_execute}, {"replaceComments", msre_fn_replaceComments_execute},
  {"jsDecode", msre_fn_jsDecode_execute}, {"urlDecode", msre_fn_urlDecode_execute},
  {"urlDecodeUni", msre_fn_urlDecodeUni_execute}, {"utf8toUnicode", msre_fn_utf8Unicode_execute},
  {"htmlEntityDecode", msre_fn_htmlEntityDecode_execute}, {"normalizePath", msre_fn_normalizePath_execute},
  {"normalizePathWin", msre_fn_normalizePathWin_execute}, {NULL, NULL}};
static int hexval(int c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }
static void puthex(const unsigned char *s, long n) { for (long i = 0; i < n; i++) printf("%02x", s[i]); }
int main(int argc, char **argv) {
  load_map(argv[1], 20127);
  static char line[1 << 20];
  apr_pool_t pool;
  while (fgets(line, sizeof line, stdin)) {
    char *sp = strchr(line, ' '); if (!sp) continue; *sp = 0;
    char *hex = sp + 1; size_t hl = strcspn(hex, "\r\n"); hex[hl] = 0;
    long n = hl / 2; unsigned char *raw = malloc(n + 1);
    for (long i = 0; i < n; i++) raw[i] = hexval(hex[2*i]) * 16 + hexval(hex[2*i+1]);
    /* re.c: var->value = apr_pstrmemdup(mptmp, var->value, var->value_len) */
    char *value = apr_pstrmemdup(&pool, (char *)raw, n); long len = n;
    printf("0:"); puthex((unsigned char *)value, len);
    char *names = line, *tok;
    while ((tok = strsep(&names, ",")) != NULL) {
      if (!*tok) continue;
      tfn_t fn = NULL; for (int k = 0; TF[k].name; k++) if (!strcmp(TF[k].name, tok)) fn = TF[k].fn;
      if (!fn) { printf(" ERR"); break; }
      char *rval = NULL; long rlen = -1;
      int ch = fn(&pool, (unsigned char *)value, len, &rval, &rlen);
      value = rval; len = rlen;
      printf(" %d:", ch); puthex((unsigned char *)value, len);
    }
    printf("\n"); fflush(stdout);
  }
  return 0;
}
