#include <stdio.h>
#include "acmp.h"
static int hexval(int c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }
int main(int argc, char **argv) {
  ACMP *p = acmp_create(0, NULL);
  if (!strcmp(argv[1], "file")) {
    FILE *fd = fopen(argv[2], "r"); char buf[8193];
    while (fgets(buf, sizeof buf, fd)) {           /* msre_op_pmFromFile_param_init line handling */
      char *start = buf, *end;
      while (isspace((unsigned char)*start) && *start) start++;
      end = buf + strlen(buf);
      if (end > start) end--;
      while (end > start && isspace((unsigned char)*end)) end--;
      if (end > start) *(++end) = '\0';
      if (start == end || *start == '#') continue;
      acmp_add_pattern(p, start, NULL, NULL, end - start);
    }
  } else {                                           /* msre_op_pm_param_init */
    const char *phrase = argv[2], *next;
    for (;;) {
      while (isspace((unsigned char)*phrase) && *phrase) phrase++;
      if (!*phrase) break;
      next = phrase; while (!isspace((unsigned char)*next) && *next) next++;
      acmp_add_pattern(p, phrase, NULL, NULL, next - phrase);
      phrase = next;
    }
  }
  acmp_prepare(p);
  static char line[1 << 20];
  while (fgets(line, sizeof line, stdin)) {
    size_t hl = strcspn(line, "\r\n"); line[hl] = 0; size_t n = hl / 2;
    char *data = malloc(n + 1);
    for (size_t i = 0; i < n; i++) data[i] = hexval(line[2*i]) * 16 + hexval(line[2*i+1]);
    const char *match = NULL; ACMPT pt; pt.parser = p; pt.ptr = NULL;
    int rc = (n == 0) ? 0 : acmp_process_quick(&pt, &match, data, n);   /* msre_op_pm_execute: empty -> no match */
    if (rc) printf("1 %s\n", match); else printf("0\n");
    fflush(stdout); free(data);
  }
  return 0;
}
