/*
 * ProFTPD: mod_digest - File hashing/checksumming module
 *
 * Copyright (c) Mathias Berchtold <mb@smartftp.com>
 * Copyright (c) 2016 TJ Saunders <tj@castaglia.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_digest.a$
 * $Libraries: -lcrypto$
 */

#include "conf.h"

#define MOD_DIGEST_VERSION      "mod_digest/2.0.0"

/* Define the custom commands/responses used. */
#ifndef C_XCRC
# define C_XCRC		"XCRC"
#endif
#ifndef C_XMD5
# define C_XMD5		"XMD5"
#endif
#ifndef C_XSHA1
# define C_XSHA1	"XSHA1"
#endif
#ifndef C_XSHA256
# define C_XSHA256	"XSHA256"
#endif

#ifndef R_556
# define R_556		"556"
#endif

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030304
# error "ProFTPD 1.3.3 or later required"
#endif

#if !defined(HAVE_OPENSSL) && !defined(PR_USE_OPENSSL)
# error "OpenSSL support required (--enable-openssl)"
#else
# include <openssl/bio.h>
# include <openssl/evp.h>
# include <openssl/err.h>
#endif

module digest_module;

static int digest_engine = TRUE;
static pool *digest_pool = NULL;

/* Digest algorithms supported by mod_digest. */
#define DIGEST_ALGO_CRC32		0x0001
#ifndef OPENSSL_NO_MD5
# define DIGEST_ALGO_MD5		0x0002
#else
# define DIGEST_ALGO_MD5		0x0000
#endif /* OPENSSL_NO_MD5 */
#ifndef OPENSSL_NO_SHA
# define DIGEST_ALGO_SHA1		0x0004
#else
# define DIGEST_ALGO_SHA1		0x0000
#endif /* OPENSSL_NO_SHA */
#ifndef OPENSSL_NO_SHA256
# define DIGEST_ALGO_SHA256		0x0008
#else
# define DIGEST_ALGO_SHA256		0x0000
#endif /* OPENSSL_NO_SHA256 */

#define DIGEST_DEFAULT_ALGOS \
  (DIGEST_ALGO_CRC32|DIGEST_ALGO_MD5|DIGEST_ALGO_SHA1|DIGEST_ALGO_SHA256)

static unsigned long digest_algos = DIGEST_DEFAULT_ALGOS;

static const char *trace_channel = "digest";

#if PROFTPD_VERSION_NUMBER < 0x0001030602
# define PR_STR_FL_HEX_USE_UC			0x0001
# define PR_STR_FL_HEX_USE_LC			0x0002
# define pr_str_bin2hex         		digest_bin2hex

static char *digest_bin2hex(pool *p, const unsigned char *buf, size_len,
    int flags) {
  static const char *hex_lc = "0123456789abcdef", *hex_uc = "0123456789ABCDEF";
  register unsigned int i;
  const char *hex_vals;
  char *hex, *ptr;
  size_t hex_len;

  if (p == NULL ||
      buf == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (len == 0) {
    return pstrdup(p, "");
  }

  /* By default, we use lowercase hex values. */
  hex_vals = hex_lc;
  if (flags & PR_STR_FL_HEX_USE_UC) {
    hex_vals = hex_uc;
  }


  hex_len = (len * 2) + 1;
  hex = palloc(p, hex_len);

  ptr = hex;
  for (i = 0; i < len; i++) {
    *ptr++ = hex_vals[buf[i] >> 4];
    *ptr++ = hex_vals[buf[i] % 16];
  }
  *ptr = '\0';

  return hex;
}
#endif

/* CRC32 implementation, as OpenSSL EVP_MD.  The following OpenSSL files
 * used as templates:
 *
 *  crypto/evp/m_md2.c
 *  crypto/md2/md2.c
 */

#define CRC32_BLOCK		4
#define CRC32_DIGEST_LENGTH	4

typedef struct crc32_ctx_st {
  uint32_t crc32_table[256];
  uint32_t data;
} CRC32_CTX;

static int CRC32_Init(CRC32_CTX *ctx) {
  register unsigned int i;

  /* Initialize the lookup table.   The magic number in the loop is the official
   * polynomial used by CRC32 in PKZip.
   */

  for (i = 0; i < sizeof(ctx->crc32_table); i++) {
    register unsigned int j;
    uint32_t crc;

    crc = i;
    for (j = 8; j > 0; j--) {
      if (crc & 1) {
        crc = (crc >> 1) ^ 0xEDB88320;
      } else {
        crc >>= 1;
      }
    }

    ctx->crc32_table[i] = crc;
  }

  ctx->data = 0xffffffff;
  return 1;
}

#define CRC32(ctx, c, b) (ctx->crc32_table[((int)(c) ^ (b)) & 0xff] ^ ((c) >> 8))
#define DOCRC(ctx, c, d)  c = CRC32(ctx, c, *d++)

static int CRC32_Update(CRC32_CTX *ctx, const unsigned char *data,
    size_t datasz) {

  if (datasz == 0) {
    return 1;
  }

  while (datasz > 0) {
    DOCRC(ctx, ctx->data, data);
    datasz--;
  }

  return 1;
}

static int CRC32_Final(unsigned char *md, CRC32_CTX *ctx) {
  uint32_t crc;

  crc = ctx->data;
  crc ^= 0xffffffff;
  crc = htonl(crc);

  memcpy(md, &crc, sizeof(crc));
  return 1;
}

static int crc32_init(EVP_MD_CTX *ctx) {
  return CRC32_Init(ctx->md_data);
}

static int crc32_update(EVP_MD_CTX *ctx, const void *data, size_t datasz) {
  return CRC32_Update(ctx->md_data, data, datasz);
}

static int crc32_final(EVP_MD_CTX *ctx, unsigned char *md) {
  return CRC32_Final(md, ctx->md_data);
}

static const EVP_MD crc32_md = {
  NID_undef,
  NID_undef,
  CRC32_DIGEST_LENGTH,
  0,
  crc32_init,
  crc32_update,
  crc32_final,
  NULL,
  NULL,
  EVP_PKEY_NULL_method,
  CRC32_BLOCK,
  sizeof(EVP_MD *) + sizeof(CRC32_CTX)
};

static const EVP_MD *EVP_crc32(void) {
  return &crc32_md;
}

static const char *get_errors(void) {
  unsigned int count = 0;
  unsigned long error_code;
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *error_data = NULL, *str = "(unknown)";
  int error_flags = 0;

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  if (error_code) {
    bio = BIO_new(BIO_s_mem());
  }

  while (error_code) {
    pr_signals_handle();

    if (error_flags & ERR_TXT_STRING) {
      BIO_printf(bio, "\n  (%u) %s [%s]", ++count,
        ERR_error_string(error_code, NULL), error_data);

    } else {
      BIO_printf(bio, "\n  (%u) %s", ++count,
        ERR_error_string(error_code, NULL));
    }

    error_data = NULL;
    error_flags = 0;
    error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
    str = pstrdup(session.pool, data);
  }
  if (bio != NULL) {
    BIO_free(bio);
  }

  return str;
}

/* Configuration handlers
 */

/* Usage: DigestAlgorithms algo1 ... */
MODRET set_digestalgorithms(cmd_rec *cmd) {
  config_rec *c;
  unsigned long algos = 0UL;

  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL|CONF_ANON);

  /* We need at least ONE algorithm. */
  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  if (strcasecmp(cmd->argv[1], "all") == 0) {
    algos = DIGEST_DEFAULT_ALGOS;

  } else {
    register unsigned int i;

    for (i = 1; i < cmd->argc; i++) {
      if (strcasecmp(cmd->argv[i], "crc32") == 0) {
        algos |= DIGEST_ALGO_CRC32;

      } else if (strcasecmp(cmd->argv[i], "md5") == 0) {
#ifndef OPENSSL_NO_MD5
        algos |= DIGEST_ALGO_MD5;
#else
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "installed OpenSSL does not support '", cmd->argv[i], "' DigestAlgorithm", NULL));
#endif /* OPENSSL_NO_MD5 */

      } else if (strcasecmp(cmd->argv[i], "sha1") == 0) {
#ifndef OPENSSL_NO_SHA
        algos |= DIGEST_ALGO_SHA1;
#else
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "installed OpenSSL does not support '", cmd->argv[i], "' DigestAlgorithm", NULL));
#endif /* OPENSSL_NO_SHA */

      } else if (strcasecmp(cmd->argv[i], "sha256") == 0) {
#ifndef OPENSSL_NO_SHA256
        algos |= DIGEST_ALGO_SHA256;
#else
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "installed OpenSSL does not support '", cmd->argv[i], "' DigestAlgorithm", NULL));
#endif /* OPENSSL_NO_SHA256 */

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
          "unknown/unsupported DigestAlgorithm: ", cmd->argv[i], NULL));
      }
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = algos;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* usage: DigestEngine on|off */
MODRET set_digestengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED(cmd);
}

/* usage: DigestMaxSize len */
MODRET set_digestmaxsize(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *endp = NULL;
  size_t lValue;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL|CONF_ANON);

#ifdef HAVE_STRTOULL
  lValue = strtoull(cmd->argv[1], &endp, 10);
#else
  lValue = strtoul(cmd->argv[1], &endp, 10);
#endif /* HAVE_STRTOULL */

  if (endp && *endp)
    CONF_ERROR(cmd, "requires a unsigned size_t value");

  if(lValue == 0)
    CONF_ERROR(cmd, "requires a value greater than zero");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(size_t));
  *((size_t *) c->argv[0]) = lValue;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

/* returns 1 if enabled. 0 otherwise */
static int digest_isenabled(unsigned long algo) {
  if (digest_algos & algo) {
    return TRUE;
  }

  return FALSE;
}

/* returns 1 if found. 0 otherwise */
static int digest_getmaxsize(size_t *pValue)
{
  int nRet = 0;
  config_rec *c = NULL;

  if(!pValue)
    return 0;

  /* Lookup config */
  c = find_config(CURRENT_CONF, CONF_PARAM, "DigestMaxSize", FALSE);
  if(c) {
    *pValue = *(size_t*)(c->argv[0]);
    nRet = 1;
  }
  return nRet;
}

static int check_file(pool *p, const char *path, off_t start, size_t len,
    struct stat *st) {

  if (!S_ISREG(st->st_mode)) {
    pr_trace_msg(trace_channel, 2, "path '%s' is not a regular file", path);
    errno = EINVAL;
    return -1;
  }

  if (start > 0) {
    if (start > st->st_size) {
      pr_log_debug(DEBUG3, MOD_DIGEST_VERSION
        ": requested offset (%" PR_LU " bytes) for path '%s' exceeds file size "
        "(%lu bytes)", (pr_off_t) start, path, (unsigned long) st->st_size);
      errno = EINVAL;
      return -1;
    }
  }

  if (len > 0) {
    if (start + len > st->st_size) {
      pr_log_debug(DEBUG3, MOD_DIGEST_VERSION
        ": requested offset/length (offset %" PR_LU " bytes, length %lu bytes) "
        "for path '%s' exceeds file size (%lu bytes)", (pr_off_t) start,
        (unsigned long) len, path, (unsigned long) st->st_size);
      errno = EINVAL;
      return -1;
    }
  }

  return 0;
}

/* Note that this is implemented in a case-INSENSITIVE manner, in order to
 * protect any unfortunate case-insensitive filesystems (such as HFS on
 * Mac, even though it is case-preserving).
 */
static int blacklisted_file(const char *path) {
  int res = FALSE;

  if (strncasecmp("/dev/full", path, 10) == 0 ||
      strncasecmp("/dev/null", path, 10) == 0 ||
      strncasecmp("/dev/random", path, 12) == 0 ||
      strncasecmp("/dev/urandom", path, 13) == 0 ||
      strncasecmp("/dev/zero", path, 10) == 0) {
    res = TRUE;
  }

  return res;
}

static int get_digest(pool *p, const char *path, off_t start, size_t len,
    const EVP_MD *md, unsigned char *digest, unsigned int *digest_len) {
  int res, xerrno = 0;
  pr_fh_t *fh;
  struct stat st;
  unsigned char *buf;
  size_t bufsz;
  EVP_MD_CTX md_ctx;

  fh = pr_fsio_open(path, O_RDONLY);
  if (fh == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1, "unable to read '%s': %s", path,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  res = pr_fsio_fstat(fh, &st);
  if (res < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1, "unable to stat '%s': %s", path,
      strerror(xerrno));
    (void) pr_fsio_close(fh);

    errno = xerrno;
    return -1;
  }

  if (len == 0) {
    /* Automatically calculate the appropriate length. */
    len = (st.st_size - start);
  }

  res = check_file(p, path, start, len, &st);
  if (res < 0) {
    xerrno = errno;
    (void) pr_fsio_close(fh);
    errno = xerrno;
    return -1;
  }

  /* Determine the optimal block size for reading. */
  fh->fh_iosz = bufsz = st.st_blksize;

  if (pr_fsio_lseek(fh, start, SEEK_SET) == (off_t) -1) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 1, "error seeking to offset %" PR_LU
      " in '%s': %s", (pr_off_t) start, path, strerror(xerrno));

    (void) pr_fsio_close(fh);
    errno = xerrno;
    return -1;
  }

  EVP_MD_CTX_init(&md_ctx);
  if (EVP_DigestInit_ex(&md_ctx, md, NULL) != 1) {
    pr_log_debug(DEBUG1, MOD_DIGEST_VERSION
      ": error preparing digest context: %s", get_errors());
    (void) pr_fsio_close(fh);
    errno = EPERM;
    return -1;
  }

  buf = palloc(p, bufsz);
  res = pr_fsio_read(fh, (char *) buf, bufsz);
  while (res > 0 && len > 0) {
    pr_signals_handle();

    if (EVP_DigestUpdate(&md_ctx, buf, res) != 1) {
      pr_log_debug(DEBUG1, MOD_DIGEST_VERSION
        ": error updating digest: %s", get_errors());
    }

    len -= res;
    res = pr_fsio_read(fh, (char *) buf, bufsz);
  }

  if (len != 0) {
    /* XXX How would this happen?  Premature EOF? */
  }

  (void) pr_fsio_close(fh);

  if (EVP_DigestFinal_ex(&md_ctx, digest, digest_len) != 1) {
    pr_log_debug(DEBUG1, MOD_DIGEST_VERSION
      ": error finishing digest: %s", get_errors());
    errno = EPERM;
    return -1;
  }

  return 0;
}

static char *digest_calculatehash(cmd_rec *cmd, const EVP_MD *md,
    const char *pszFile, off_t lStart, size_t lLen) {
  int res;
  unsigned char *digest = NULL;
  unsigned int digest_len;
  char *hex_digest;

  digest_len = EVP_MD_size(md);
  digest = palloc(cmd->tmp_pool, digest_len);

  res = get_digest(cmd->tmp_pool, pszFile, lStart, lLen, md, digest,
    &digest_len);
  if (res == 0) {
    hex_digest = pr_str_bin2hex(cmd->tmp_pool, digest, digest_len,
      PR_STR_FL_HEX_USE_UC);
  }

  return hex_digest;
}

/* Command handlers
 */
MODRET digest_cmdex(cmd_rec *cmd) {
  char *path;
  struct stat sbuf;

  CHECK_CMD_MIN_ARGS(cmd, 2);

  /* Note: no support for "CMD file endposition" because it's implemented differently by other FTP servers */
  if(cmd->argc == 3) {
    pr_response_add_err(R_501, "Invalid number of arguments.");
    return PR_ERROR((cmd));
  }

  /* XXX Watch out for paths with spaces in them! */
  path = dir_realpath(cmd->tmp_pool, cmd->argv[1]);

  if (path != NULL &&
      blacklisted_file(path) == TRUE) {
    pr_log_debug(DEBUG8, MOD_DIGEST_VERSION
      ": rejecting request to checksum blacklisted special file '%s'", path);
    pr_response_add_err(R_550, "%s: %s", (char *) cmd->arg, strerror(EPERM));
    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (!path ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, path, NULL) ||
      pr_fsio_stat(path, &sbuf) == -1) {
    pr_response_add_err(R_550,"%s: %s", (char *) cmd->argv[1], strerror(errno));
    return PR_ERROR(cmd);
  }

  if (!S_ISREG(sbuf.st_mode)) {
    pr_response_add_err(R_550,"%s: Not a regular file", (char *) cmd->argv[1]);
    return PR_ERROR(cmd);

  } else {
    off_t lStart = 0;
    off_t lEnd = 0;
    size_t lLength;
    size_t lMaxSize;
    const EVP_MD *md = NULL;

    if(cmd->argc > 3) {
      char *endp = NULL;

#ifdef HAVE_STRTOULL
      lStart = strtoull(cmd->argv[2], &endp, 10);
#else
      lStart = strtoul(cmd->argv[2], &endp, 10);
#endif /* HAVE_STRTOULL */

      if (endp && *endp) {
        pr_response_add_err(R_501, "%s requires a startposition greater than or equal to 0", (char *) cmd->argv[0]);
        return PR_ERROR(cmd);
      }

#ifdef HAVE_STRTOULL
      lEnd = strtoull(cmd->argv[3], &endp, 10);
#else
      lEnd = strtoul(cmd->argv[3], &endp, 10);
#endif /* HAVE_STRTOULL */

      if ( (endp && *endp)) {
        pr_response_add_err(R_501, "%s requires a endposition greater than 0", (char *) cmd->argv[0]);
        return PR_ERROR(cmd);
      }
    }

    pr_log_debug(DEBUG10, MOD_DIGEST_VERSION
      ": '%s' Start=%llu, End=%llu", cmd->arg, (unsigned long long)lStart, (unsigned long long)lEnd);

    if(lStart > lEnd) {
      pr_response_add_err(R_501, "%s requires endposition greater than startposition", (char *) cmd->argv[0]);
      return PR_ERROR(cmd);
    }

    lLength = lEnd - lStart;

    if(digest_getmaxsize(&lMaxSize) == 1 && lLength > lMaxSize) {
      pr_response_add_err(R_556, "%s: Length (%zu) greater than DigestMaxSize (%zu) config value", cmd->arg, lLength, lMaxSize);
      return PR_ERROR(cmd);
    }

    if (strcmp(cmd->argv[0], C_XCRC) == 0) {
      md = EVP_crc32();

    } else if(strcmp(cmd->argv[0], C_XMD5) == 0) {
      md = EVP_md5();

    } else if(strcmp(cmd->argv[0], C_XSHA256) == 0) {
      md = EVP_sha256();

    } else if(strcmp(cmd->argv[0], C_XSHA1) == 0) {
      md = EVP_sha1();
    }

    if(md) {
      char *pszValue;
      pszValue = digest_calculatehash(cmd, md, path, lStart, lLength);
      if(pszValue) {
        pr_response_add(R_250, "%s", pszValue);
        return PR_HANDLED(cmd);
      }

      /* TODO: More detailed error message? */
      pr_response_add_err(R_550, "%s: Failed to calculate hash", cmd->arg);

    } else {
      pr_response_add_err(R_550, "%s: No hash algorithm available", cmd->arg);
    }
  }

  return PR_ERROR(cmd);
}

MODRET digest_post_pass(cmd_rec *cmd) {
  config_rec *c;

  if (digest_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  c = find_config(CURRENT_CONF, CONF_PARAM, "DigestEngine", FALSE);
  if (c != NULL) {
    digest_engine = *((int *) c->argv[0]);
  }

  if (digest_engine == FALSE) {
    return PR_DECLINED(cmd);
  }
  
  c = find_config(CURRENT_CONF, CONF_PARAM, "DigestAlgorithms", FALSE);
  if (c != NULL) {
    digest_algos = *((unsigned long *) c->argv[0]);
  }

  return PR_DECLINED(cmd);
}

MODRET digest_xcrc(cmd_rec *cmd) {
  if (digest_isenabled(DIGEST_ALGO_CRC32) != TRUE) {
    pr_log_debug(DEBUG9, MOD_DIGEST_VERSION
      ": unable to handle %s command: CRC32 disabled by DigestAlgorithms",
      (char *) cmd->argv[0]);
    return PR_DECLINED(cmd);
  }

  return digest_cmdex(cmd);
}

MODRET digest_xmd5(cmd_rec *cmd) {
  if (digest_isenabled(DIGEST_ALGO_MD5) != TRUE) {
    pr_log_debug(DEBUG9, MOD_DIGEST_VERSION
      ": unable to handle %s command: MD5 disabled by DigestAlgorithms",
      (char *) cmd->argv[0]);
    return PR_DECLINED(cmd);
  }

  return digest_cmdex(cmd);
}

MODRET digest_xsha1(cmd_rec *cmd) {
  if (digest_isenabled(DIGEST_ALGO_SHA1) != TRUE) {
    pr_log_debug(DEBUG9, MOD_DIGEST_VERSION
      ": unable to handle %s command: SHA1 disabled by DigestAlgorithms",
      (char *) cmd->argv[0]);
    return PR_DECLINED(cmd);
  }

  return digest_cmdex(cmd);
}

MODRET digest_xsha256(cmd_rec *cmd) {
  if (digest_isenabled(DIGEST_ALGO_SHA256) != TRUE) {
    pr_log_debug(DEBUG9, MOD_DIGEST_VERSION
      ": unable to handle %s command: SHA256 disabled by DigestAlgorithms",
      (char *) cmd->argv[0]);
    return PR_DECLINED(cmd);
  }

  return digest_cmdex(cmd);
}

/* Event listeners
 */

#if defined(PR_SHARED_MODULE)
static void digest_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp((char *) event_data, "mod_digest.c") == 0) {
    pr_event_unregister(&digest_module, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void digest_restart_ev(const void *event_data, void *user_data) {
}

/* Initialization routines
 */

static int digest_init(void) {
  digest_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(digest_pool, MOD_DIGEST_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&digest_module, "core.module-unload", digest_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&digest_module, "core.restart", digest_restart_ev, NULL);

  return 0;
}

static int digest_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "DigestEngine", FALSE);
  if (c != NULL) {
    digest_engine = *((int *) c->argv[0]);
  }

  if (digest_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "DigestAlgorithms", FALSE);
  if (c != NULL) {
    digest_algos = *((unsigned long *) c->argv[0]);
  }

  if (digest_algos & DIGEST_ALGO_CRC32) {
    pr_feat_add(C_XCRC);
    pr_help_add(C_XCRC, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  if (digest_algos & DIGEST_ALGO_MD5) {
    pr_feat_add(C_XMD5);
    pr_help_add(C_XMD5, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  if (digest_algos & DIGEST_ALGO_SHA1) {
    pr_feat_add(C_XSHA1);
    pr_help_add(C_XSHA1, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  if (digest_algos & DIGEST_ALGO_SHA256) {
    pr_feat_add(C_XSHA256);
    pr_help_add(C_XSHA256, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  return 0;
}

/* Module API tables
 */

static cmdtable digest_cmdtab[] = {
  { CMD, C_XCRC,	G_READ, digest_xcrc,	TRUE, FALSE, CL_READ|CL_INFO },
  { CMD, C_XMD5,	G_READ, digest_xmd5,	TRUE, FALSE, CL_READ|CL_INFO },
  { CMD, C_XSHA1,	G_READ, digest_xsha1,	TRUE, FALSE, CL_READ|CL_INFO },
  { CMD, C_XSHA256,	G_READ, digest_xsha256,	TRUE, FALSE, CL_READ|CL_INFO },
  { POST_CMD,	C_PASS, G_NONE,	digest_post_pass, TRUE, FALSE },
  { 0, NULL }
};

static conftable digest_conftab[] = {
  { "DigestAlgorithms",	set_digestalgorithms,	NULL },
  { "DigestEngine",	set_digestengine,	NULL },
  { "DigestMaxSize",	set_digestmaxsize,	NULL },

  { NULL }
};

module digest_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "digest",

  /* Module configuration table */
  digest_conftab,

  /* Module command handler table */
  digest_cmdtab,

  /* Module auth handler table */
  NULL,

  /* Module initialization function */
  digest_init,

  /* Session initialization function */
  digest_sess_init,

  /* Module version */
  MOD_DIGEST_VERSION
};
