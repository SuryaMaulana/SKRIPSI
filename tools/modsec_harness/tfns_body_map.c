#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <strings.h>
typedef struct { int dummy; } apr_pool_t;
static void *apr_palloc(apr_pool_t *p, size_t n) { return malloc(n); }
static char *apr_pstrmemdup(apr_pool_t *p, const char *s, size_t n) { char *r = malloc(n + 1); memcpy(r, s, n); r[n] = 0; return r; }
#define apr_isspace(c) isspace((unsigned char)(c))
#define NBSP 160
#define VALID_HEX(X) (((X >= '0')&&(X <= '9')) || ((X >= 'a')&&(X <= 'f')) || ((X >= 'A')&&(X <= 'F')))
#define ISODIGIT(X) ((X >= '0')&&(X <= '7'))
#define UNICODE_ERROR_CHARACTERS_MISSING    -1
#define UNICODE_ERROR_INVALID_ENCODING      -2
#define UNICODE_ERROR_OVERLONG_CHARACTER    -3
#define UNICODE_ERROR_RESTRICTED_CHARACTER  -4
#define UNICODE_ERROR_DECODING_ERROR        -5
static int *unicode_map_table = NULL; static void load_map(const char *path, unsigned cp);
static unsigned int unicode_codepage = 0;
static unsigned char x2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}
static unsigned char xsingle2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));

    return digit;
}
char *utf8_unicode_inplace_ex(apr_pool_t *mp, unsigned char *input, long int input_len, int *changed) {
    int unicode_len = 0;
    unsigned int d = 0;
    unsigned char c, *utf;
    char *rval, *data;
    unsigned int i, len;
    unsigned int bytes_left = input_len;

    assert(input != NULL);

    *changed = 0;
    /* RFC3629 states that UTF-8 are encoded using sequences of 1 to 4 octets. */
    /* Max size per character should fit in 4 bytes (%u01020304) */
    len = input_len * 10 + 1;
    data = rval = apr_palloc(mp, len);
    if (rval == NULL) return NULL;

    for (i = 0; i < bytes_left;) {
        unicode_len = 0; d = 0;
        utf = (unsigned char *)&input[i];
        c = *utf;

        /* If first byte begins with binary 0 it may be single byte encoding */
        if ((c & 0x80) == 0) {
            if (c == 0) {
                unicode_len = 2;
                d = utf[1];
            }
        }
        /* If first byte begins with binary 110 it is two byte encoding*/
        else if ((c & 0xE0) == 0xC0) {
            /* check we have at least two bytes */
            if (bytes_left < 2) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            /* check second byte starts with binary 10 */
            else if ((utf[1] & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            else {
                unicode_len = 2;
                /* compute character number */
                d = ((c & 0x1F) << 6) | (utf[1] & 0x3F);
            }
        }
        /* If first byte begins with binary 1110 it is three byte encoding */
        else if ((c & 0xF0) == 0xE0) {
            /* check we have at least three bytes */
            if (bytes_left < 3) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            /* check second byte starts with binary 10 */
            else if ((utf[1] & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            /* check third byte starts with binary 10 */
            else if (((*(utf + 2)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            else {
                unicode_len = 3;
                /* compute character number */
                d = ((c & 0x0F) << 12) | ((utf[1] & 0x3F) << 6) | (*(utf + 2) & 0x3F);
            }
        }
        /* If first byte begins with binary 11110 it is four byte encoding */
        else if ((c & 0xF8) == 0xF0) {
            /* restrict characters to UTF-8 range (U+0000 - U+10FFFF)*/
            if (c >= 0xF5) unicode_len = UNICODE_ERROR_RESTRICTED_CHARACTER;
            /* check we have at least four bytes */
            else if (bytes_left < 4) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            /* check second byte starts with binary 10 */
            else if ((utf[1] & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            /* check third byte starts with binary 10 */
            else if (((*(utf + 2)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            /* check forth byte starts with binary 10 */
            else if (((*(utf + 3)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            else {
                unicode_len = 4;
                /* compute character number */
                d = ((c & 0x07) << 18) | ((utf[1] & 0x3F) << 12) | ((*(utf + 2) & 0x3F) << 6) | (*(utf + 3) & 0x3F);
            }
        }
        /* invalid UTF-8 character number range (RFC 3629) */
        if ((d >= 0xD800) && (d <= 0xDFFF)) unicode_len = UNICODE_ERROR_RESTRICTED_CHARACTER;
        /* check for overlong */
        if ((unicode_len == 4) && (d < 0x010000)) unicode_len = UNICODE_ERROR_OVERLONG_CHARACTER;
        /* three byte could be represented with less bytes */
        if ((unicode_len == 3) && (d < 0x0800)) unicode_len = UNICODE_ERROR_OVERLONG_CHARACTER;
        /* two byte could be represented with less bytes */
        if ((unicode_len == 2) && (d < 0x80)) unicode_len = UNICODE_ERROR_OVERLONG_CHARACTER;

        if (unicode_len > 0) {
            i += unicode_len;
            sprintf(data, "%%u%04x", d);
            data += 6;
            *changed = 1;
        }
        else {
            /* any other first byte is invalid (RFC 3629), so assume it's an ASCII character */
            *data++ = c;
            i++;
        }
    }

    *data = '\0';
    return rval;
}
int js_decode_nonstrict_inplace(unsigned char *input, long int input_len) {
    unsigned char *d = (unsigned char *)input;
    long int i, count;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {
        if (input[i] == '\\') {
            /* Character is an escape. */

            if (   (i + 5 < input_len) && (input[i + 1] == 'u')
                    && (VALID_HEX(input[i + 2])) && (VALID_HEX(input[i + 3]))
                    && (VALID_HEX(input[i + 4])) && (VALID_HEX(input[i + 5])) )
            {
                /* \uHHHH */

                /* Use only the lower byte. */
                *d = x2c(&input[i + 4]);

                /* Full width ASCII (ff01 - ff5e) needs 0x20 added */
                if (   (*d > 0x00) && (*d < 0x5f)
                        && ((input[i + 2] == 'f') || (input[i + 2] == 'F'))
                        && ((input[i + 3] == 'f') || (input[i + 3] == 'F')))
                {
                    (*d) += 0x20;
                }

                d++;
                count++;
                i += 6;
            }
            else if (   (i + 3 < input_len) && (input[i + 1] == 'x')
                    && VALID_HEX(input[i + 2]) && VALID_HEX(input[i + 3])) {
                /* \xHH */
                *d++ = x2c(&input[i + 2]);
                count++;
                i += 4;
            }
            else if ((i + 1 < input_len) && ISODIGIT(input[i + 1])) {
                /* \OOO (only one byte, \000 - \377) */
                char buf[4];
                int j = 0;

                while((i + 1 + j < input_len)&&(j < 3)) {
                    buf[j] = input[i + 1 + j];
                    j++;
                    if (!ISODIGIT(input[i + 1 + j])) break;
                }
                buf[j] = '\0';

                if (j > 0) {
                    /* Do not use 3 characters if we will be > 1 byte */
                    if ((j == 3) && (buf[0] > '3')) {
                        j = 2;
                        buf[j] = '\0';
                    }
                    *d++ = (unsigned char)strtol(buf, NULL, 8);
                    i += 1 + j;
                    count++;
                }
            }
            else if (i + 1 < input_len) {
                /* \C */
                unsigned char c = input[i + 1];
                switch(input[i + 1]) {
                    case 'a' :
                        c = '\a';
                        break;
                    case 'b' :
                        c = '\b';
                        break;
                    case 'f' :
                        c = '\f';
                        break;
                    case 'n' :
                        c = '\n';
                        break;
                    case 'r' :
                        c = '\r';
                        break;
                    case 't' :
                        c = '\t';
                        break;
                    case 'v' :
                        c = '\v';
                        break;
                        /* The remaining (\?,\\,\',\") are just a removal
                         * of the escape char which is default.
                         */
                }

                *d++ = c;
                i += 2;
                count++;
            }
            else {
                /* Not enough bytes */
                while(i < input_len) {
                    *d++ = input[i++];
                    count++;
                }
            }
        }
        else {
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';

    return count;
}
int urldecode_uni_nonstrict_inplace_ex(unsigned char *input, long int input_len, int *changed) {
    unsigned char *d = input;
    long int i, count, fact, j, xv;
    int Code, hmap = -1;

    *changed = 0;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {
        if (input[i] == '%') {
            /* Character is a percent sign. */

            if ((i + 1 < input_len)&&( (input[i + 1] == 'u')||(input[i + 1] == 'U') )) {
                /* IIS-specific %u encoding. */
                if (i + 5 < input_len) {
                    /* We have at least 4 data bytes. */
                    if (  (VALID_HEX(input[i + 2]))&&(VALID_HEX(input[i + 3]))
                            &&(VALID_HEX(input[i + 4]))&&(VALID_HEX(input[i + 5])) )
                    {

                        Code = 0;
                        fact = 1;

                        if (unicode_map_table != NULL && unicode_codepage > 0)  {

                            for(j=5; j>=2; j--)   {
                                if (isxdigit((input[i+j])))  {
                                    if ((input[i+j])>=97)    {
                                        xv = ( (input[i+j]) - 97) + 10;
                                    } else if ( (input[i+j]) >= 65)  {
                                        xv = ((input[i+j]) - 65) + 10;
                                    } else {
                                        xv = (input[i+j]) - 48;
                                    }
                                    Code += (xv * fact);
                                    fact *= 16;
                                }
                            }

                            if(Code >= 0 && Code <= 65535)  {
                                hmap = unicode_map_table[Code];
                            }
                        }

                        if(hmap != -1)  {
                            *d = hmap;
                        } else {
                            /* We first make use of the lower byte here, ignoring the higher byte. */
                            *d = x2c(&input[i + 4]);

                            /* Full width ASCII (ff01 - ff5e) needs 0x20 added */
                            if (   (*d > 0x00) && (*d < 0x5f)
                                    && ((input[i + 2] == 'f') || (input[i + 2] == 'F'))
                                    && ((input[i + 3] == 'f') || (input[i + 3] == 'F')))
                            {
                                (*d) += 0x20;
                            }
                        }
                        d++;
                        count++;
                        i += 6;
                        *changed = 1;
                    } else {
                        /* Invalid data, skip %u. */
                        *d++ = input[i++];
                        *d++ = input[i++];
                        count += 2;
                    }
                } else {
                    /* Not enough bytes (4 data bytes), skip %u. */
                    *d++ = input[i++];
                    *d++ = input[i++];
                    count += 2;
                }
            }
            else {
                /* Standard URL encoding. */

                /* Are there enough bytes available? */
                if (i + 2 < input_len) {
                    /* Yes. */

                    /* Decode a %xx combo only if it is valid.
                     */
                    char c1 = input[i + 1];
                    char c2 = input[i + 2];

                    if (VALID_HEX(c1) && VALID_HEX(c2)) {
                        *d++ = x2c(&input[i + 1]);
                        count++;
                        i += 3;
                        *changed = 1;
                    } else {
                        /* Not a valid encoding, skip this % */
                        *d++ = input[i++];
                        count++;
                    }
                } else {
                    /* Not enough bytes available, skip this % */
                    *d++ = input[i++];
                    count++;
                }
            }
        }
        else {
            /* Character is not a percent sign. */
            if (input[i] == '+') {
                *d++ = ' ';
                *changed = 1;
            } else {
                *d++ = input[i];
            }

            count++;
            i++;
        }
    }

    *d = '\0';

    return count;
}
int urldecode_nonstrict_inplace_ex_plus(unsigned char *input, long int input_len, int plus_to_space, int *invalid_count, int *changed) {
    unsigned char *d = (unsigned char *)input;
    long int i, count;

    *changed = 0;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {
        if (input[i] == '%') {
            /* Character is a percent sign. */

            /* Are there enough bytes available? */
            if (i + 2 < input_len) {
                char c1 = input[i + 1];
                char c2 = input[i + 2];

                if (VALID_HEX(c1) && VALID_HEX(c2)) {
                    /* Valid encoding - decode it. */
                    *d++ = x2c(&input[i + 1]);
                    count++;
                    i += 3;
                    *changed = 1;
                } else {
                    /* Not a valid encoding, skip this % */
                    *d++ = input[i++];
                    count ++;
                    (*invalid_count)++;
                }
            } else {
                /* Not enough bytes available, copy the raw bytes. */
                *d++ = input[i++];
                count ++;
                (*invalid_count)++;
            }
        } else {
            /* Character is not a percent sign. */
            if (plus_to_space && input[i] == '+') {
                *d++ = ' ';
                *changed = 1;
            } else {
                *d++ = input[i];
            }
            count++;
            i++;
        }
    }

    *d = '\0';

    return count;
}
int urldecode_nonstrict_inplace_ex(unsigned char *input, long int input_len, int *invalid_count, int *changed) {
    return urldecode_nonstrict_inplace_ex_plus(input, input_len, 1, invalid_count, changed);
}
#define NAMED_ENTITY(name_lit, character) \
    { (name_lit), sizeof(name_lit) - 1, (unsigned char)(character) }

static const struct {
    const char *name;
    size_t len;
    unsigned char ch;
} msc_html_named_entities[] = {
    /* Generated by tools/gen-html-entities.py from
     * https://html.spec.whatwg.org/entities.json -- do not edit by hand.
     *
     * Every entity expanding to a single code point in U+0000..U+007F,
     * plus NBSP (U+00A0) and SOFT HYPHEN (U+00AD).  44 entries.
     *
     * Case-insensitive matching collapses these spec distinctions:
     *   &GT; = U+003E wins over &Gt; = U+226B
     *   &LT; = U+003C wins over &Lt; = U+226A
     *   &colon; = U+003A wins over &Colon; = U+2237
     *   &verbar; = U+007C wins over &Verbar; = U+2016
     *   &vert; = U+007C wins over &Vert; = U+2016
     */
    NAMED_ENTITY("amp",              '&'),
    NAMED_ENTITY("apos",             '\''),
    NAMED_ENTITY("ast",              '*'),
    NAMED_ENTITY("bsol",             '\\'),
    NAMED_ENTITY("colon",            ':'),
    NAMED_ENTITY("comma",            ','),
    NAMED_ENTITY("commat",           '@'),
    NAMED_ENTITY("diacriticalgrave", '`'),
    NAMED_ENTITY("dollar",           '$'),
    NAMED_ENTITY("equals",           '='),
    NAMED_ENTITY("excl",             '!'),
    NAMED_ENTITY("grave",            '`'),
    NAMED_ENTITY("gt",               '>'),
    NAMED_ENTITY("hat",              '^'),
    NAMED_ENTITY("lbrace",           '{'),
    NAMED_ENTITY("lbrack",           '['),
    NAMED_ENTITY("lcub",             '{'),
    NAMED_ENTITY("lowbar",           '_'),
    NAMED_ENTITY("lpar",             '('),
    NAMED_ENTITY("lsqb",             '['),
    NAMED_ENTITY("lt",               '<'),
    NAMED_ENTITY("midast",           '*'),
    NAMED_ENTITY("nbsp",             NBSP),
    NAMED_ENTITY("newline",          '\n'),
    NAMED_ENTITY("nonbreakingspace", NBSP),
    NAMED_ENTITY("num",              '#'),
    NAMED_ENTITY("percnt",           '%'),
    NAMED_ENTITY("period",           '.'),
    NAMED_ENTITY("plus",             '+'),
    NAMED_ENTITY("quest",            '?'),
    NAMED_ENTITY("quot",             '\"'),
    NAMED_ENTITY("rbrace",           '}'),
    NAMED_ENTITY("rbrack",           ']'),
    NAMED_ENTITY("rcub",             '}'),
    NAMED_ENTITY("rpar",             ')'),
    NAMED_ENTITY("rsqb",             ']'),
    NAMED_ENTITY("semi",             ';'),
    NAMED_ENTITY("shy",              0xAD),
    NAMED_ENTITY("sol",              '/'),
    NAMED_ENTITY("tab",              '\t'),
    NAMED_ENTITY("underbar",         '_'),
    NAMED_ENTITY("verbar",           '|'),
    NAMED_ENTITY("vert",             '|'),
    NAMED_ENTITY("verticalline",     '|'),
};

#undef NAMED_ENTITY
static int msc_html_named_entity_lookup(const char *name, size_t name_len,
                                        unsigned char *out) {
    size_t n = sizeof(msc_html_named_entities) / sizeof(msc_html_named_entities[0]);
    size_t i;
    for (i = 0; i < n; i++) {
        if (name_len == msc_html_named_entities[i].len &&
            strncasecmp(name, msc_html_named_entities[i].name, name_len) == 0) {
            *out = msc_html_named_entities[i].ch;
            return 1;
        }
    }
    return 0;
}
int html_entities_decode_inplace(apr_pool_t *mp, unsigned char *input, int input_len) {
    unsigned char *d = input;
    int i, count;

    if ((input == NULL)||(input_len <= 0)) return 0;

    i = count = 0;
    while((i < input_len)&&(count < input_len)) {
        int z, copy = 1;

        /* Require an ampersand and at least one character to
         * start looking into the entity.
         */
        if ((input[i] == '&')&&(i + 1 < input_len)) {
            int k, j = i + 1;

            if (input[j] == '#') {
                /* Numerical entity. */
                copy++;

                if (!(j + 1 < input_len)) goto HTML_ENT_OUT; /* Not enough bytes. */
                j++;

                if ((input[j] == 'x')||(input[j] == 'X')) {
                    /* Hexadecimal entity. */
                    copy++;

                    if (!(j + 1 < input_len)) goto HTML_ENT_OUT; /* Not enough bytes. */
                    j++; /* j is the position of the first digit now. */

                    k = j;
                    while((j < input_len)&&(isxdigit(input[j]))) j++;
                    if (j > k) { /* Do we have at least one digit? */
                        /* Decode the entity. */
                        char *x = apr_pstrmemdup(mp, (const char *)&input[k], j - k);
                        *d++ = (unsigned char)strtol(x, NULL, 16);
                        count++;

                        /* Skip over the semicolon if it's there. */
                        if ((j < input_len)&&(input[j] == ';')) i = j + 1;
                        else i = j;

                        continue;
                    } else {
                        goto HTML_ENT_OUT;
                    }
                } else {
                    /* Decimal entity. */
                    k = j;
                    while((j < input_len)&&(isdigit(input[j]))) j++;
                    if (j > k) { /* Do we have at least one digit? */
                        /* Decode the entity. */
                        char *x = apr_pstrmemdup(mp, (const char *)&input[k], j - k);
                        *d++ = (unsigned char)strtol(x, NULL, 10);
                        count++;

                        /* Skip over the semicolon if it's there. */
                        if ((j < input_len)&&(input[j] == ';')) i = j + 1;
                        else i = j;

                        continue;
                    } else {
                        goto HTML_ENT_OUT;
                    }
                }
            } else {
                /* Text entity. */

                k = j;
                while((j < input_len)&&(isalnum(input[j]))) j++;
                if (j > k) { /* Do we have at least one character? */
                    unsigned char decoded = 0;

                    if (!msc_html_named_entity_lookup((const char *)&input[k],
                                                      j - k, &decoded)) {
                        /* Unknown entity: copy the raw data over. */
                        copy = j - k + 1;
                        goto HTML_ENT_OUT;
                    }
                    *d++ = decoded;
                    count++;

                    /* Skip over the semicolon if it's there. */
                    if ((j < input_len)&&(input[j] == ';')) i = j + 1;
                    else i = j;

                    continue;
                }
            }
        }

HTML_ENT_OUT:

        for(z = 0; ((z < copy) && (count < input_len)); z++) {
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';

    return count;
}
int normalize_path_inplace(unsigned char *input, int input_len, int win, int *changed) {
    unsigned char *src;
    unsigned char *dst;
    unsigned char *end;
    int ldst = 0;
    int hitroot = 0;
    int done = 0;
    int relative;
    int trailing;

    *changed = 0;

    /* Need at least one byte to normalize */
    if (input_len <= 0) return 0;

    /*
     * ENH: Deal with UNC and drive letters?
     */

    src = dst = input;
    end = input + (input_len - 1);
    ldst = 1;

    relative = ((*input == '/') || (win && (*input == '\\'))) ? 0 : 1;
    trailing = ((*end == '/') || (win && (*end == '\\'))) ? 1 : 0;


    while (!done && (src <= end) && (dst <= end)) {
        /* Convert backslash to forward slash on Windows only. */
        if (win) {
            if (*src == '\\') {
                *src = '/';
                *changed = 1;
            }
            if ((src < end) && (*(src + 1) == '\\')) {
                *(src + 1) = '/';
                *changed = 1;
            }
        }

        /* Always normalize at the end of the input. */
        if (src == end) {
            done = 1;
        }

        /* Skip normalization if this is NOT the end of the path segment. */
        else if (*(src + 1) != '/') {
            goto copy; /* Skip normalization. */
        }

        /*** Normalize the path segment. ***/

        /* Could it be an empty path segment? */
        if ((src != end) && *src == '/') {
            /* Ignore */
            *changed = 1;
            goto copy; /* Copy will take care of this. */
        }

        /* Could it be a back or self reference? */
        else if (*src == '.') {

            /* Back-reference? */
            if ((dst > input) && (*(dst - 1) == '.')) {
                /* If a relative path and either our normalization has
                 * already hit the rootdir, or this is a backref with no
                 * previous path segment, then mark that the rootdir was hit
                 * and just copy the backref as no normilization is possible.
                 */
                if (relative && (hitroot || ((dst - 2) <= input))) {
                    hitroot = 1;

                    goto copy; /* Skip normalization. */
                }

                /* Remove backreference and the previous path segment. */
                dst -= 3;
                while ((dst > input) && (*dst != '/')) {
                    dst--;
                }

                /* But do not allow going above rootdir. */
                if (dst <= input) {
                    hitroot = 1;
                    dst = input;

                    /* Need to leave the root slash if this
                     * is not a relative path and the end was reached
                     * on a backreference.
                     */
                    if (!relative && (src == end)) {
                        dst++;
                    }
                }

                if (done) goto length; /* Skip the copy. */
                src++;

                *changed = 1;
            }

            /* Relative Self-reference? */
            else if (dst == input) {
                *changed = 1;

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                src++;
            }

            /* Self-reference? */
            else if (*(dst - 1) == '/') {
                *changed = 1;

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                dst--;
                src++;
            }
        }

        /* Found a regular path segment. */
        else if (dst > input) {
            hitroot = 0;
        }

copy:
        /*** Copy the byte if required. ***/

        /* Skip to the last forward slash when multiple are used. */
        if (*src == '/') {
            unsigned char *oldsrc = src;

            while (   (src < end)
                    && ((*(src + 1) == '/') || (win && (*(src + 1) == '\\'))) )
            {
                src++;
            }
            if (oldsrc != src) *changed = 1;

            /* Do not copy the forward slash to the root
             * if it is not a relative path.  Instead
             * move over the slash to the next segment.
             */
            if (relative && (dst == input)) {
                src++;
                goto length; /* Skip the copy */
            }
        }

        *(dst++) = *(src++);

length:
        ldst = (dst - input);
    }

    /* Make sure that there is not a trailing slash in the
     * normalized form if there was not one in the original form.
     */
    if (!trailing && (dst > input) && *(dst - 1) == '/') {
        ldst--;
        dst--;
    }

    /* Always NUL terminate */
    *dst = '\0';

    return ldst;
}
int css_decode_inplace(unsigned char *input, long int input_len) {
    unsigned char *d = (unsigned char *)input;
    long int i, j, count;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {

        /* Is the character a backslash? */
        if (input[i] == '\\') {

            /* Is there at least one more byte? */
            if (i + 1 < input_len) {
                i++; /* We are not going to need the backslash. */

                /* Check for 1-6 hex characters following the backslash */
                j = 0;
                while (    (j < 6)
                        && (i + j < input_len)
                        && (VALID_HEX(input[i + j])))
                {
                    j++;
                }

                if (j > 0) { /* We have at least one valid hexadecimal character. */
                    int fullcheck = 0;

                    /* For now just use the last two bytes. */
                    switch (j) {
                        /* Number of hex characters */
                        case 1:
                            *d++ = xsingle2c(&input[i]);
                            break;

                        case 2:
                        case 3:
                            /* Use the last two from the end. */
                            *d++ = x2c(&input[i + j - 2]);
                            break;

                        case 4:
                            /* Use the last two from the end, but request
                             * a full width check.
                             */
                            *d = x2c(&input[i + j - 2]);
                            fullcheck = 1;
                            break;

                        case 5:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);

                            /* Do full check if first byte is 0 */
                            if (input[i] == '0') {
                                fullcheck = 1;
                            }
                            else {
                                d++;
                            }
                            break;

                        case 6:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);

                            /* Do full check if first/second bytes are 0 */
                            if (    (input[i] == '0')
                                    && (input[i + 1] == '0')
                               ) {
                                fullcheck = 1;
                            }
                            else {
                                d++;
                            }
                            break;
                    }

                    /* Full width ASCII (0xff01 - 0xff5e) needs 0x20 added */
                    if (fullcheck) {
                        if (   (*d > 0x00) && (*d < 0x5f)
                                && ((input[i + j - 3] == 'f') ||
                                    (input[i + j - 3] == 'F'))
                                && ((input[i + j - 4] == 'f') ||
                                    (input[i + j - 4] == 'F')))
                        {
                            (*d) += 0x20;
                        }

                        d++;
                    }

                    /* We must ignore a single whitespace after a hex escape */
                    if ((i + j < input_len) && isspace(input[i + j])) {
                        j++;
                    }

                    /* Move over. */
                    count++;
                    i += j;
                }

                /* No hexadecimal digits after backslash */
                else if (input[i] == '\n') {
                    /* A newline character following backslash is ignored. */
                    i++;
                }

                /* The character after backslash is not a hexadecimal digit, nor a newline. */
                else {
                    /* Use one character after backslash as is. */
                    *d++ = input[i++];
                    count++;
                }
            }

            /* No characters after backslash. */
            else {
                /* Do not include backslash in output (continuation to nothing) */
                i++; 
            }
        }

        /* Character is not a backslash. */
        else {
            /* Copy one normal character to output. */
            *d++ = input[i++];
            count++;
        }
    }

    /* Terminate output string. */
    *d = '\0';

    return count;
}
static int msre_fn_cmdline_execute(apr_pool_t *mptmp, unsigned char *input,
        long int input_len, char **rval, long int *rval_len)
{
    int space = 0;
    unsigned char *s = input;

    if (rval == NULL) return -1;

    *rval = (char *)input;
    /* Check characters */
    for ( ; *input; input++ ) {
        switch(*input) {
            /* remove some characters */
            case '"':
            case '\'':
            case '\\':
            case '^':
                continue;
                /* replace some characters to space (only one) */
            case ' ':
            case ',':
            case ';':
            case '\t':
            case '\r':
            case '\n':
                if (!space) {
                    *s++ = ' ';
                    space++;
                }
                break;
            case '/':
            case '(':
                /* remove space before / or ( */
                if (space) s--;
                space = 0;
                *s++ = *input;
                break;
                /* copy normal characters */
            default :
                *s++ = tolower(*input);
                space = 0;
        }
    }

    *s = 0;
    *rval_len = strlen(*rval);
    return 1;
}
static int msre_fn_lowercase_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int i;
    int changed = 0;

    if (rval == NULL) return -1;
    *rval = NULL;

    i = 0;
    while(i < input_len) {
        int x = input[i];
        input[i] = tolower(x);
        if (x != input[i]) changed = 1;
        i++;
    }

    *rval = (char *)input;
    *rval_len = input_len;

    return changed;
}
static int msre_fn_removeNulls_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int i, j;
    int changed = 0;

    i = j = 0;
    while(i < input_len) {
        if (input[i] == '\0') {
            changed = 1;
        } else {
            input[j] = input[i];
            j++;
        }
        i++;
    }

    *rval = (char *)input;
    *rval_len = j;

    return changed;
}
static int msre_fn_compressWhitespace_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int i, j, count;
    int changed = 0;
    int inwhitespace = 0;

    i = j = count = 0;
    while(i < input_len) {
        if (isspace(input[i])||(input[i] == NBSP)) {
            if (inwhitespace) changed = 1;
            inwhitespace = 1;
            count++;
        } else {
            inwhitespace = 0;
            if (count) {
                input[j] = ' ';
                count = 0;
                j++;
            }
            input[j] = input[i];
            j++;
        }
        i++;
    }

    if (count) {
        input[j] = ' ';
        j++;
    }

    *rval = (char *)input;
    *rval_len = j;

    return changed;
}
static int msre_fn_cssDecode_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int length;

    length = css_decode_inplace(input, input_len);
    *rval = (char *)input;
    *rval_len = length;

    return (*rval_len == input_len ? 0 : 1);
}
static int msre_fn_removeWhitespace_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int i, j;
    int changed = 0;

    i = j = 0;
    while(i < input_len) {
        if (isspace(input[i])||(input[i] == NBSP)) {
            /* do nothing */
            changed = 1;
        } else {
            input[j] = input[i];
            j++;
        }
        i++;
    }

    *rval = (char *)input;
    *rval_len = j;

    return changed;
}
static int msre_fn_removeCommentsChar_execute(apr_pool_t *mptmp, unsigned char *input,
        long int input_len, char **rval, long int *rval_len)
{
    long int i, j;
    int changed = 0;

    i = j = 0;
    while(i < input_len) {
        if ((input[i] == '/')&&(i + 1 < input_len)&&(input[i + 1] == '*')) {
            changed = 1;
            i += 2;
        } else if ((input[i] == '*')&&(i + 1 < input_len)&&(input[i + 1] == '/')) {
            changed = 1;
            i += 2;
        } else if ((input[i] == '<')&&(i + 1 < input_len)&&(input[i + 1] == '!')&&
                    (i + 2 < input_len)&&(input[i+2] == '-')&&(i + 3 < input_len)&&
                    (input[i + 3] == '-')) {
            changed = 1;
            i += 4;
        } else if ((input[i] == '-')&&(i + 1 < input_len)&&(input[i + 1] == '-')&&
                    (i + 2 < input_len)&&(input[i+2] == '>'))   {
            changed = 1;
            i += 3;
        } else if ((input[i] == '-')&&(i + 1 < input_len)&&(input[i + 1] == '-')) {
            changed = 1;
            i += 2;
        } else if (input[i] == '#') {
            changed = 1;
            i++;
        } else {
            input[j] = input[i];
            i++;
            j++;
        }
    }
    input[j] = '\0';

    *rval = (char *)input;
    *rval_len = j;

    return changed;
}
static int msre_fn_replaceComments_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int i, j, incomment;
    int changed = 0;

    i = j = incomment = 0;
    while(i < input_len) {
        if (incomment == 0) {
            if ((input[i] == '/')&&(i + 1 < input_len)&&(input[i + 1] == '*')) {
                changed = 1;
                incomment = 1;
                i += 2;
            } else {
                input[j] = input[i];
                i++;
                j++;
            }
        } else {
            if ((input[i] == '*')&&(i + 1 < input_len)&&(input[i + 1] == '/')) {
                incomment = 0;
                i += 2;
                input[j] = ' ';
                j++;
            } else {
                i++;
            }
        }
    }

    if (incomment) {
        input[j++] = ' ';
    }

    *rval = (char *)input;
    *rval_len = j;

    return changed;
}
static int msre_fn_jsDecode_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int length;

    length = js_decode_nonstrict_inplace(input, input_len);
    *rval = (char *)input;
    *rval_len = length;

    return (*rval_len == input_len ? 0 : 1);
}
static int msre_fn_urlDecode_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int length;
    int invalid_count;
    int changed;

    length = urldecode_nonstrict_inplace_ex(input, input_len, &invalid_count, &changed);
    *rval = (char *)input;
    *rval_len = length;

    return changed;
}
static int msre_fn_urlDecodeUni_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    long int length;
    int changed;

    length = urldecode_uni_nonstrict_inplace_ex(input, input_len, &changed);
    *rval = (char *)input;
    *rval_len = length;

    return changed;
}
static int msre_fn_utf8Unicode_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    int changed = 0;

    *rval = (char *)utf8_unicode_inplace_ex(mptmp, input, input_len, &changed);
    *rval_len = strlen(*rval);

    return changed;
}
static int msre_fn_htmlEntityDecode_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    *rval_len = html_entities_decode_inplace(mptmp, input, input_len);
    *rval = (char *)input;

    return (*rval_len == input_len ? 0 : 1);
}
static int msre_fn_normalizePath_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    int changed;

    *rval_len = normalize_path_inplace(input, input_len, 0, &changed);
    *rval = (char *)input;

    return changed;
}
static int msre_fn_normalizePathWin_execute(apr_pool_t *mptmp, unsigned char *input,
    long int input_len, char **rval, long int *rval_len)
{
    int changed;

    *rval_len = normalize_path_inplace(input, input_len, 1, &changed);
    *rval = (char *)input;

    return changed;
}
