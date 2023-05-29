
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
	unsigned long total[2];	/*!< number of bytes processed  */
	unsigned long state[8];	/*!< intermediate digest state  */
	unsigned char buffer[64];	/*!< data block being processed */

	unsigned char ipad[64];	/*!< HMAC: inner padding        */
	unsigned char opad[64];	/*!< HMAC: outer padding        */
	int is224;		/*!< 0 => SHA-256, else SHA-224 */
} sha2_context;

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * SHA-256 context setup
 */
void sha2_starts( sha2_context *ctx, int is224 );
static void sha2_process( sha2_context *ctx, const unsigned char data[64] );

void sha2_update( sha2_context *ctx, const unsigned char *input, size_t ilen );

static const unsigned char sha2_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-256 final digest
 */
void sha2_finish( sha2_context *ctx, unsigned char output[32] );

/*
 * output = SHA-256( input buffer )
 */
void sha2( const unsigned char *input, size_t ilen,
           unsigned char output[32], int is224 );
/*
 * SHA-256 HMAC context setup
 */
void sha2_hmac_starts( sha2_context *ctx, const unsigned char *key, size_t keylen,
                       int is224 );

/*
 * SHA-256 HMAC process buffer
 */
void sha2_hmac_update( sha2_context *ctx, const unsigned char *input, size_t ilen );

/*
 * SHA-256 HMAC final digest
 */
void sha2_hmac_finish( sha2_context *ctx, unsigned char output[32] );

/*
 * SHA-256 HMAC context reset
 */
void sha2_hmac_reset( sha2_context *ctx );

/*
 * output = HMAC-SHA-256( hmac key, input buffer )
 */
void sha2_hmac( const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char output[32], int is224 );





#ifndef min
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif

void PKCS5_PBKDF2_HMAC(unsigned char *password, size_t plen,
    unsigned char *salt, size_t slen,
    const unsigned long iteration_count, const unsigned long key_length,
    unsigned char *output);
