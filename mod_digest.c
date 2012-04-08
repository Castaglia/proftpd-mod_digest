/*
 * mod_digest - File hashing module for ProFTPD
 * Copyright (c) Mathias Berchtold <mb@smartftp.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 */

/*
 * "digest" commands module for ProFTPD
 * $Id: mod_digest.c,v 1.0.3 2011/12/02 07:25:00 mb Exp $
 */

#include "conf.h"

#include <netinet/in.h> /* htonl */

#define MOD_DIGEST_VERSION    "mod_digest/1.0.3"

#define C_XCRC  "XCRC"    /* XCRC */
#define C_XMD5  "XMD5"    /* XMD5*/
#define C_XSHA1 "XSHA1"   /* XSHA1*/
#define C_XSHA256 "XSHA256"   /* XSHA256*/

/* name for config */
#define CONFIG_DIGEST_MAXSIZE "DigestMaxSize"
#define CONFIG_DIGEST_TYPES "DigestTypes"

/* type def */
#if defined(__amd64__)
#include <inttypes.h>
typedef uint32_t U32;
typedef uint16_t UINT2;
typedef uint32_t UINT4;
#else
typedef unsigned long U32;
typedef unsigned short int UINT2;
typedef unsigned long int UINT4;
#endif

/* to avoid dependency of stdlib.h */
#define _min(a,b)    (((a) < (b)) ? (a) : (b))

/*
////////////////////////////////////////////////////
// classhash
*/

typedef struct classhash_struct classhash;

/* pseudo class wrapper */
struct classhash_struct {

  /* functions */
  void (*constructor)(classhash*);
  void (*deconstructor)(classhash*);
  int (*init)(classhash*);
  void (*update)(classhash*, const unsigned char *pbBuf, size_t cbBuf);
  char* (*getvalueasstring)(classhash*);

  /* variables */
  long m_cbBuffer;
  unsigned char *m_pbBuffer;
  pool *m_pool;
};


/* Returns string
   Note: free string */
static char* datatohexstring(pool *pool, const unsigned char* pbBuf, size_t nSize)
{
  char *pszRet;
  static char* szHexChars = "0123456789ABCDEF";

  if(!pbBuf)
    return 0;

  if(!pool)
    return 0;

  pszRet = (char*)pcalloc(pool, nSize * 2 + 1);
  if(pszRet)
  {
    char *pszPos = pszRet;
    size_t i;
    for(i=0; i<nSize; i++) {
      *pszPos = szHexChars[pbBuf[i] >> 4];
      pszPos++;
      *pszPos = szHexChars[pbBuf[i] % 16];
      pszPos++;
    }
    *pszPos = 0;
  }

  return pszRet;
}

/*
/////////////////////////////////////////////////////////////
// CRC32
*/

static U32 crc32_table[256];

static void crc32_inittable()
{
  /* This is the official polynomial used by CRC32 in PKZip.
    Often times the polynomial shown reversed as 0x04C11DB7.
   dwPolynomial = 0xEDB88320;
  */

  int i,j;
  U32 crc;

  for(i = 0; i < 256; i++) {
    crc = i;
    for (j = 8; j > 0; j--) {
      if (crc & 1)
        crc = (crc >> 1) ^ 0xEDB88320;
      else
        crc >>= 1;
    }
    crc32_table[i] = crc;

    //pr_log_debug(DEBUG2, MOD_DIGEST_VERSION": %x", crc);
  }
}

static int crc32_init(classhash *pThis)
{
  pThis->m_cbBuffer = 4;
  pThis->m_pbBuffer = (unsigned char*)pcalloc(pThis->m_pool, pThis->m_cbBuffer);
  if(pThis->m_pbBuffer) {
    *((U32*)pThis->m_pbBuffer) = 0xffffffff;
    return 1;
  }
  return 0;
}

static void crc32_constructor(classhash *pThis)
{
  pThis->m_pbBuffer = 0;
  pThis->m_cbBuffer = 0;
}

static void crc32_deconstructor(classhash *pThis)
{
  if(pThis->m_pbBuffer) {
    // free(pThis->m_pbBuffer);
    pThis->m_pbBuffer = 0;
  }
}

#define CRC32(c, b) (crc32_table[((int)(c) ^ (b)) & 0xff] ^ ((c) >> 8))
#define DOCRC(c, buf)  c = CRC32(c, *buf++)

static void crc32_update(classhash *pThis, const unsigned char *pbBuf, size_t cbBuf)
{
  if (pbBuf == 0)
    return;

  while (cbBuf >= 8)
  {
    /* unfold loop */
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);

    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);

    cbBuf -= 8;
  }

  while(cbBuf > 0)
  {
    DOCRC(*((U32*)pThis->m_pbBuffer), pbBuf);
    cbBuf--;
  }
}


static char* crc32_getvalueasstring(classhash* pThis)
{
  U32 crc = *((U32*)pThis->m_pbBuffer);
  crc ^= 0xffffffff;
  crc = htonl(crc); /* to be tested on both big/little endian */
  return datatohexstring(pThis->m_pool, (unsigned char*)&crc, 4);
}

/* hash classes */
static classhash classCRC32 = {
  crc32_constructor,
  crc32_deconstructor,
  crc32_init,
  crc32_update,
  crc32_getvalueasstring,
  0,
  0,
  0
};


/*
 /////////////////////////////////////////////////////////////
 // MD5
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#define PROTO_LIST(list) list

/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;


/* Constants for MD5Transform routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5Transform PROTO_LIST ((UINT4 [4], const unsigned char*));
static void Encode PROTO_LIST ((unsigned char *, UINT4 *, size_t));
static void Decode PROTO_LIST ((UINT4 *, const unsigned char *, size_t));

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions. */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void MD5Init (MD5_CTX *context)
/* context */
{
  context->count[0] = context->count[1] = 0;
  /* Load magic initialization constants.
*/
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
static void MD5Update (MD5_CTX *context, const unsigned char *input, size_t inputLen)
/* context */
/* input block */
/* length of input block */
{
  size_t i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (size_t)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ( (context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))
    context->count[1]++;
  context->count[1] += ((UINT4)inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible. */
  if (inputLen >= partLen)
  {
    memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);
    MD5Transform(context->state, context->buffer);

    for (i = partLen; i + 63 < inputLen; i += 64)
      MD5Transform(context->state, &input[i]);

    index = 0;
  }
  else
    i = 0;

  /* Buffer remaining input */
  memcpy((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
static void MD5Final (unsigned char digest[16], MD5_CTX *context)
/* message digest */
/* context */
{
  unsigned char bits[8];
  size_t index, padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64. */
  index = (size_t)((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);

  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  /* Store state in digest */
  Encode (digest, context->state, 16);

  /* Zeroize sensitive information. */
  memset ((POINTER)context, 0, sizeof (*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform(UINT4 state[4], const unsigned char *block)
/* block should always be 64 bytes long */
{
  UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode (x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information. */
  memset ((POINTER)x, 0, sizeof (x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void Encode (unsigned char *output, UINT4 *input, size_t len)
{
  size_t i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (unsigned char)(input[i] & 0xff);
    output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
    output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
    output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4.
 */
static void Decode(UINT4 *output, const unsigned char *input, size_t len)
{
  size_t i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
 output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |
   (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);
}

/* MD5 Hash class */

static int md5_init(classhash *pThis)
{
  pThis->m_cbBuffer = sizeof(MD5_CTX);
  pThis->m_pbBuffer = (unsigned char*)pcalloc(pThis->m_pool, sizeof(MD5_CTX));
  if(pThis->m_pbBuffer) {
    MD5Init((MD5_CTX*)pThis->m_pbBuffer);
    return 1;
  }
  return 0;
}

static void md5_constructor(classhash *pThis)
{
  pThis->m_pbBuffer = 0;
  pThis->m_cbBuffer = 0;
}

static void md5_deconstructor(classhash *pThis)
{
  if(pThis->m_pbBuffer) {
    // free(pThis->m_pbBuffer);
    pThis->m_pbBuffer = 0;
  }
}

static void md5_update(classhash *pThis, const unsigned char *pbBuf, size_t cbBuf)
{
  MD5Update((MD5_CTX*)pThis->m_pbBuffer, pbBuf, cbBuf);
}

static char* md5_getvalueasstring(classhash* pThis)
{
  unsigned char digest[16];
  MD5Final(digest, (MD5_CTX*)pThis->m_pbBuffer);
  return datatohexstring(pThis->m_pool, digest, sizeof(digest));
}


/* hash classes */
static classhash classMD5 = {
  md5_constructor,
  md5_deconstructor,
  md5_init,
  md5_update,
  md5_getvalueasstring,
  0,
  0,
  0
};

/*
 SHA256
 Tom St Denis, tomstdenis@yahoo.com
 */

typedef struct {
    U32 state[8], length, curlen;
    unsigned char buf[64];
}
SHA256_STATE;

/* the K array */
static const U32 K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* Various logical functions */
#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z)  ((x & y) ^ (x & z) ^ (y & z))
#define S(x, n)   (((x)>>((n)&31))|((x)<<(32-((n)&31))))
#define R(x, n)   ((x)>>(n))
#define Sigma0(x) (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x) (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x) (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x) (S(x, 17) ^ S(x, 19) ^ R(x, 10))

/* compress 512-bits */
static void sha_compress(SHA256_STATE * md)
{
    U32 S[8], W[64], t0, t1;
    int i;

    /* copy state into S */
    for (i = 0; i < 8; i++)
        S[i] = md->state[i];

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++)
        W[i] = (((U32) md->buf[(4 * i) + 0]) << 24) |
            (((U32) md->buf[(4 * i) + 1]) << 16) |
            (((U32) md->buf[(4 * i) + 2]) << 8) |
            (((U32) md->buf[(4 * i) + 3]));

    /* fill W[16..63] */
    for (i = 16; i < 64; i++)
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

    /* Compress */
    for (i = 0; i < 64; i++) {
        t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
        t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + t0;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = t0 + t1;
    }

    /* feedback */
    for (i = 0; i < 8; i++)
        md->state[i] += S[i];
}

/* init the SHA state */
static void sha_init(SHA256_STATE * md)
{
    md->curlen = md->length = 0;
    md->state[0] = 0x6A09E667UL;
    md->state[1] = 0xBB67AE85UL;
    md->state[2] = 0x3C6EF372UL;
    md->state[3] = 0xA54FF53AUL;
    md->state[4] = 0x510E527FUL;
    md->state[5] = 0x9B05688CUL;
    md->state[6] = 0x1F83D9ABUL;
    md->state[7] = 0x5BE0CD19UL;
}

static void sha_process(SHA256_STATE * md, const unsigned char *buf, int len)
{
    while (len--) {
        /* copy byte */
        md->buf[md->curlen++] = *buf++;

        /* is 64 bytes full? */
        if (md->curlen == 64) {
            sha_compress(md);
            md->length += 512;
            md->curlen = 0;
        }
    }
}

static void sha_done(SHA256_STATE * md, unsigned char hash[32])
{
    int i;

    /* increase the length of the message */
    md->length += md->curlen * 8;

    /* append the '1' bit */
    md->buf[md->curlen++] = 0x80;

    /* if the length is currenlly above 56 bytes we append zeros
                               * then compress.  Then we can fall back to padding zeros and length
                               * encoding like normal.
                             */
    if (md->curlen >= 56) {
        for (; md->curlen < 64;)
            md->buf[md->curlen++] = 0;
        sha_compress(md);
        md->curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    for (; md->curlen < 56;)
        md->buf[md->curlen++] = 0;

    /* since all messages are under 2^32 bits we mark the top bits zero */
    for (i = 56; i < 60; i++)
        md->buf[i] = 0;

    /* append length */
    for (i = 60; i < 64; i++)
        md->buf[i] = (md->length >> ((63 - i) * 8)) & 255;
    sha_compress(md);

    /* copy output */
    for (i = 0; i < 32; i++)
        hash[i] = (md->state[i >> 2] >> (((3 - i) & 3) << 3)) & 255;
}

/* SHA256 Hash class */

static int sha256_init(classhash *pThis)
{
  pThis->m_cbBuffer = sizeof(SHA256_STATE);
  pThis->m_pbBuffer = (unsigned char*)pcalloc(pThis->m_pool, sizeof(SHA256_STATE));
  if(pThis->m_pbBuffer) {
    sha_init((SHA256_STATE*)pThis->m_pbBuffer);
    return 1;
  }
  return 0;
}

static void sha256_constructor(classhash *pThis)
{
  pThis->m_pbBuffer = 0;
  pThis->m_cbBuffer = 0;
}

static void sha256_deconstructor(classhash *pThis)
{
  if(pThis->m_pbBuffer) {
    // free(pThis->m_pbBuffer);
    pThis->m_pbBuffer = 0;
  }
}

static void sha256_update(classhash *pThis, const unsigned char *pbBuf, size_t cbBuf)
{
  sha_process((SHA256_STATE*)pThis->m_pbBuffer, pbBuf, cbBuf);
}

static char* sha256_getvalueasstring(classhash* pThis)
{
  unsigned char digest[32];
  sha_done((SHA256_STATE*)pThis->m_pbBuffer, digest);
  return datatohexstring(pThis->m_pool, digest, sizeof(digest));
}

/* hash classes */
static classhash classSHA256 = {
  sha256_constructor,
  sha256_deconstructor,
  sha256_init,
  sha256_update,
  sha256_getvalueasstring,
  0,
  0,
  0
};


/*
 SHA-1 in C
 By Steve Reid <sreid@sea-to-sky.net>
 100% Public Domain
 Reference: http://cvs.haskell.org/darcs/cabal_examples/wash/Utility-0.3.10/sha1lib.c

 #define LITTLE_ENDIAN * This should be #define'd if true.
 */

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} SHA1_CTX;

static void SHA1Transform(unsigned long state[5], const unsigned char *buffer);
static void SHA1Init(SHA1_CTX* context);
static void SHA1Update(SHA1_CTX* context, const unsigned char *data, unsigned long len);
static void SHA1Final(unsigned char digest[20], SHA1_CTX* context);

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifdef LITTLE_ENDIAN
#define blk0(i) (block.l[i] = (rol(block.l[i],24)&0xFF00FF00) \
    |(rol(block.l[i],8)&0x00FF00FF))
#else
#define blk0(i) block.l[i]
#endif
#define blk(i) (block.l[i&15] = rol(block.l[(i+13)&15]^block.l[(i+8)&15] \
    ^block.l[(i+2)&15]^block.l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */
static void SHA1Transform(unsigned long state[5], const unsigned char *buffer)
{
unsigned long a, b, c, d, e;
typedef union {
    unsigned char c[64];
    unsigned long l[16];
} CHAR64LONG16;
CHAR64LONG16 block;

    memcpy(&block, buffer, sizeof(block));

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
}


/* SHA1Init - Initialize new context */
static void SHA1Init(SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */
static void SHA1Update(SHA1_CTX* context, const unsigned char *data, unsigned long len)
{
unsigned long i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

static void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
  unsigned long i;
  unsigned char finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
    SHA1Update(context, (const unsigned char *)"\200", 1);
    while ((context->count[0] & 504) != 448) {
        SHA1Update(context, (const unsigned char *)"\0", 1);
    }
    SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++) {
        digest[i] = (unsigned char)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
    /* Wipe variables */
    i = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(finalcount, 0, 8);
#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite its own static vars */
    SHA1Transform(context->state, context->buffer);
#endif
}

/* SHA1 Hash class */

static int sha1_init(classhash *pThis)
{
  pThis->m_cbBuffer = sizeof(SHA1_CTX);
  pThis->m_pbBuffer = (unsigned char*)pcalloc(pThis->m_pool, sizeof(SHA1_CTX));
  if(pThis->m_pbBuffer) {
    SHA1Init((SHA1_CTX*)pThis->m_pbBuffer);
    return 1;
  }
  return 0;
}

static void sha1_constructor(classhash *pThis)
{
  pThis->m_pbBuffer = 0;
  pThis->m_cbBuffer = 0;
}

static void sha1_deconstructor(classhash *pThis)
{
  if(pThis->m_pbBuffer) {
    // free(pThis->m_pbBuffer);
    pThis->m_pbBuffer = 0;
  }
}

static void sha1_update(classhash *pThis, const unsigned char *pbBuf, size_t cbBuf)
{
  SHA1Update((SHA1_CTX*)pThis->m_pbBuffer, pbBuf, cbBuf);
}

static char* sha1_getvalueasstring(classhash* pThis)
{
  unsigned char digest[20];
  SHA1Final(digest, (SHA1_CTX*)pThis->m_pbBuffer);
  return datatohexstring(pThis->m_pool, digest, sizeof(digest));
}

/* hash classes */
static classhash classSHA1 = {
  sha1_constructor,
  sha1_deconstructor,
  sha1_init,
  sha1_update,
  sha1_getvalueasstring,
  0,
  0,
  0
};

/*
  digest
*/

/* DigestMaxSize */
MODRET digest_set_maxsize(cmd_rec *cmd) {
  config_rec *c = NULL;
  char *endp = NULL;
  size_t lValue;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_ANON|CONF_LIMIT|CONF_VIRTUAL);

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

  return HANDLED(cmd);
}

typedef struct {
  const char *name;
  const char *cmd;
}
digest_type_entry;

static digest_type_entry supported_digest_types[] = {
  {"crc32", C_XCRC},
  {"md5", C_XMD5},
  {"sha1", C_XSHA1},
  {"sha256", C_XSHA256},
  {"all", NULL},
  /*
   * add additional encryption types below
   */
  {NULL, NULL}
};

static digest_type_entry *get_digest_type(char *name) {
  digest_type_entry *ate = supported_digest_types;

  while (ate->name) {
    if (strcasecmp(ate->name, name) == 0)
      return ate;
    ate++;
  }
  return NULL;
}

MODRET digest_set_types(cmd_rec *cmd) {
  config_rec *c;
  array_header *ah;
  digest_type_entry *digest_entry;
  digest_type_entry **digest_handle;
  int cnt;

  CHECK_CONF(cmd, CONF_ROOT|CONF_ANON|CONF_LIMIT|CONF_VIRTUAL);

  /* Need *at least* one handler. */
  if (cmd->argc < 2)
    CONF_ERROR(cmd, "expected at least one handler type");

  c = add_config_param(cmd->argv[0], 1, NULL);
  if(!c)
    CONF_ERROR(cmd, "add_config_param() failed");

  ah = make_array(c->pool, cmd->argc - 1, sizeof(digest_type_entry *));
  if(!ah)
    CONF_ERROR(cmd, "make_array() failed");

  /* Walk through our cmd->argv. */
  for (cnt = 1; cnt < cmd->argc; cnt++) {
    digest_entry = get_digest_type(cmd->argv[cnt]);
    if (digest_entry == NULL) {
      CONF_ERROR(cmd, "unknown digest type");
    }

    digest_handle = (digest_type_entry **) push_array(ah);
    *digest_handle = digest_entry;
  }

  c->argv[0] = ah;
  c->flags |= CF_MERGEDOWN;

  return HANDLED(cmd);
}

/* returns 1 if enabled. 0 otherwise */
static int digest_isenabled(const char *szCmd)
{
  config_rec *c = NULL;
  int nRet = 0;

  if(!szCmd)
    return 0;

  /* Lookup config */
  c = find_config(CURRENT_CONF, CONF_PARAM, CONFIG_DIGEST_TYPES, FALSE);
  if(c) {
     array_header *ah = c->argv[0];
     digest_type_entry *digest_entry;
     int cnt;

     for (cnt = 0; ah && cnt < ah->nelts; cnt++) {
       digest_entry = ((digest_type_entry **) ah->elts)[cnt];

       if(strcasecmp(digest_entry->name, "all") == 0
       	  || strcasecmp(szCmd, digest_entry->cmd) == 0) {
         nRet = 1;
         break;
       }
     }
  } else {
    /* by default all are enabled */
    nRet = 1;
  }

  return nRet;
}

/* returns 1 if found. 0 otherwise */
static int digest_getmaxsize(size_t *pValue)
{
  int nRet = 0;
  config_rec *c = NULL;

  if(!pValue)
    return 0;

  /* Lookup config */
  c = find_config(CURRENT_CONF, CONF_PARAM, CONFIG_DIGEST_MAXSIZE, FALSE);
  if(c) {
    *pValue = *(size_t*)(c->argv[0]);
    nRet = 1;
  }
  return nRet;
}

#define BUFFERSIZE (8*1024)

/* Reads file and calculates hash
   Returns 1 on success. 1 on error */
static int digest_calculatefilehash(classhash* pHash, const char *pszFile, off_t lStart, size_t lLen)
{
  int nRet = 0;
  FILE *pFile;

  pr_log_debug(DEBUG10, MOD_DIGEST_VERSION
      ": digest_calculatefilehash('%s' Start=%llu Len=%zu", pszFile, (unsigned long long)lStart, lLen);

  if(lLen == 0)
    return 1;

  pFile = fopen(pszFile, "rb");
  if(pFile) {
    if(fseek(pFile, lStart, SEEK_SET) == 0) {
      /* allocate buffer */
      unsigned char *pBuffer = (unsigned char*)palloc(pHash->m_pool, BUFFERSIZE);
      if(pBuffer) {
        nRet = 1;
        while(lLen > 0) {
          size_t lSize = _min(BUFFERSIZE, lLen);

          pr_signals_handle();

          size_t lRead = fread(pBuffer, 1, lSize, pFile);
          if(lRead > 0) {
            pHash->update(pHash, pBuffer, lRead);

            lLen -= lRead;
          }
          else
          {
            /* EOF */
            break;
          }
        }
        // free(pBuffer);
      }
    }
    fclose(pFile);
  }
  return nRet;
}

/* returns hex encoded string representing the hash value. 0 otherwise.
   Note: free string.
 */
static char* digest_calculatehash(cmd_rec *cmd, classhash* pHashBase, const char *pszFile, off_t lStart, size_t lLen)
{
  char *pszValue = 0;
  classhash* pHash;

  if(!cmd)
    return 0;

  if(!pHashBase)
    return 0;

  pHash = (classhash*)palloc(cmd->tmp_pool, sizeof(classhash));
  if(pHash) {
    memcpy(pHash, pHashBase, sizeof(classhash));

    pHash->m_pool = cmd->tmp_pool;
    pHash->constructor(pHash);

    if(pHash->init(pHash)) {
      if(digest_calculatefilehash(pHash, pszFile, lStart, lLen))
        pszValue = pHash->getvalueasstring(pHash);
    }
    pHash->deconstructor(pHash);
    // free(cmd->tmp_pool, pHash);
  }
  return pszValue;
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
    return ERROR((cmd));
  }

  path = dir_realpath(cmd->tmp_pool, cmd->argv[1]);

  if (!path ||
      !dir_check(cmd->tmp_pool, cmd, cmd->group, path, NULL) ||
      pr_fsio_stat(path, &sbuf) == -1) {
    pr_response_add_err(R_550,"%s: %s", cmd->argv[1], strerror(errno));
    return ERROR(cmd);
  }
  else {
    if (!S_ISREG(sbuf.st_mode)) {
      pr_response_add_err(R_550,"%s: not a plain file.",cmd->argv[1]);
      return ERROR(cmd);
    }
    else {
      off_t lStart = 0;
      off_t lEnd = sbuf.st_size;
      size_t lLength;
      classhash *pHash = 0;
      size_t lMaxSize;

      if(cmd->argc > 3) {
        char *endp = NULL;

#ifdef HAVE_STRTOULL
        lStart = strtoull(cmd->argv[2], &endp, 10);
#else
        lStart = strtoul(cmd->argv[2], &endp, 10);
#endif /* HAVE_STRTOULL */

        if (endp && *endp) {
          pr_response_add_err(R_501, "%s requires a startposition greater than or equal to 0", cmd->argv[0]);
          return ERROR(cmd);
        }

#ifdef HAVE_STRTOULL
        lEnd = strtoull(cmd->argv[3], &endp, 10);
#else
        lEnd = strtoul(cmd->argv[3], &endp, 10);
#endif /* HAVE_STRTOULL */

        if ( (endp && *endp)) {
          pr_response_add_err(R_501, "%s requires a endposition greater than 0", cmd->argv[0]);
          return ERROR(cmd);
        }
      }

      pr_log_debug(DEBUG10, MOD_DIGEST_VERSION
      ": '%s' Start=%llu, End=%llu", cmd->arg, (unsigned long long)lStart, (unsigned long long)lEnd);

      if(lStart >= lEnd) {
          pr_response_add_err(R_501, "%s requires endposition greater than startposition", cmd->argv[0]);
          return ERROR(cmd);
      }

      lLength = lEnd - lStart;

      if(digest_getmaxsize(&lMaxSize) == 1
        && lLength > lMaxSize) {
        	// TODO: Should be replaced with R_556 once it has been defined in ftp.h
          pr_response_add_err("556", "%s: Length (%zu) greater than " CONFIG_DIGEST_MAXSIZE " (%zu) config value", cmd->arg, lLength, lMaxSize);
          return ERROR(cmd);
      }

      if(strcmp(cmd->argv[0], C_XCRC) == 0)
        pHash = &classCRC32;
      else if(strcmp(cmd->argv[0], C_XMD5) == 0)
        pHash = &classMD5;
      else if(strcmp(cmd->argv[0], C_XSHA256) == 0)
        pHash = &classSHA256;
      else if(strcmp(cmd->argv[0], C_XSHA1) == 0)
        pHash = &classSHA1;

      if(pHash) {
        char *pszValue;
        pszValue = digest_calculatehash(cmd, pHash, path, lStart, lLength);
        if(pszValue) {
          pr_response_add(R_250, "%s", pszValue);
          // free(pszValue);

          return HANDLED(cmd);
        }
        else {
          /* TODO: More detailed error message? */
          pr_response_add_err(R_550, "%s: Failed to calculate hash", cmd->arg);
        }
      }
      else {
        pr_response_add_err(R_550, "%s: No hash algorithm available", cmd->arg);
      }
      return ERROR(cmd);
    }
  }
}

MODRET digest_cmd(cmd_rec *cmd)
{
  /* Lookup config
     Note: config name is the same as the command name.
   */
  if(!digest_isenabled(cmd->argv[0]))
    return DECLINED(cmd);

  return digest_cmdex(cmd);
}

/* Initialization routines
 */

static int digest_init(void)
{
  crc32_inittable();
  return 0;
}

static int digest_sessioninit(void) {

  if(digest_isenabled(C_XCRC) == 1) {
    pr_feat_add(C_XCRC);
    pr_help_add(C_XCRC, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  if(digest_isenabled(C_XMD5) == 1) {
    pr_feat_add(C_XMD5);
    pr_help_add(C_XMD5, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  if(digest_isenabled(C_XSHA1) == 1) {
    pr_feat_add(C_XSHA1);
    pr_help_add(C_XSHA1, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  if(digest_isenabled(C_XSHA256) == 1) {
    pr_feat_add(C_XSHA256);
    pr_help_add(C_XSHA256, "<sp> pathname [<sp> startposition <sp> endposition]", TRUE);
  }

  return 0;
}


/* Module API tables
 */
static cmdtable digest_cmdtab[] = {
  { CMD, C_XCRC, G_NONE, digest_cmd, TRUE,  FALSE, CL_INFO },
  { CMD, C_XMD5, G_NONE, digest_cmd, TRUE,  FALSE, CL_INFO },
  { CMD, C_XSHA1, G_NONE, digest_cmd, TRUE, FALSE, CL_INFO },
  { CMD, C_XSHA256, G_NONE, digest_cmd, TRUE, FALSE, CL_INFO },
  { 0, NULL }
};

static conftable digest_conftab[] = {
  { CONFIG_DIGEST_MAXSIZE, digest_set_maxsize, NULL },
  { CONFIG_DIGEST_TYPES, digest_set_types, NULL },
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
  digest_sessioninit
};
