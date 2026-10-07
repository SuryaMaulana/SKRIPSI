#ifndef APR_STUB_H
#define APR_STUB_H
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
typedef size_t apr_size_t;
typedef int apr_status_t;
#define APR_SUCCESS 0
#define APR_EGENERAL 20014
typedef struct apr_pool_t { int dummy; } apr_pool_t;
static inline apr_status_t apr_pool_create(apr_pool_t **p, apr_pool_t *parent) { *p = calloc(1, sizeof(apr_pool_t)); return APR_SUCCESS; }
static inline void *apr_pcalloc(apr_pool_t *p, size_t n) { return calloc(1, n ? n : 1); }
#define apr_tolower(c) tolower((unsigned char)(c))
typedef struct { int elt_size; int nelts; int nalloc; char *elts; } apr_array_header_t;
static inline apr_array_header_t *apr_array_make(apr_pool_t *p, int n, int sz) { apr_array_header_t *a = calloc(1, sizeof *a); a->elt_size = sz; a->nalloc = n > 0 ? n : 1; a->elts = calloc(a->nalloc, sz); return a; }
static inline void *apr_array_push(apr_array_header_t *a) { if (a->nelts == a->nalloc) { a->nalloc *= 2; a->elts = realloc(a->elts, a->nalloc * a->elt_size); } return a->elts + (a->nelts++) * a->elt_size; }
static inline void *apr_array_pop(apr_array_header_t *a) { if (a->nelts <= 0) return NULL; return a->elts + (--a->nelts) * a->elt_size; }
static inline int apr_is_empty_array(const apr_array_header_t *a) { return a == NULL || a->nelts == 0; }
#endif
