/**
 *
 *    GFW.Press
 *    Copyright (C) 2016  chinashiyu ( chinashiyu@gfw.press ; http://gfw.press )
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *    
 **/

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** ASCII表 */
static unsigned char ascii[256] = { 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64 };

/** 数据块大小的字符串长度 14 */
static int SIZE_SIZE = 14;

/** IV字节长度，16 */
static int IV_SIZE = 16;

/** 噪音数据最大长度，4K */
static int NOISE_MAX = 1024 * 4;

/**
 * MD5编码
 */
int md5_encode(char * in, char * out) {

	int length = strlen(in);

	unsigned char digest[16];

	MD5_CTX *ctx = (MD5_CTX *) malloc(sizeof(MD5_CTX));

	MD5_Init(ctx);

	MD5_Update(ctx, in, length);

	MD5_Final(digest, ctx);

	int i;

	for (i = 0; i < 16; ++i) {

		sprintf(&(out[i * 2]), "%02x", (unsigned int) digest[i]);

	}

	free(ctx);

	return 32;

}

/**
 * BASE64解码
 */
int base64_decode(char *in, char *out) {

	int len;

	unsigned char *_in;

	unsigned char *_out;

	int _bytes;

	_in = (unsigned char *) in;

	while (ascii[*(_in++)] <= 63) {
		;
	}

	_bytes = (_in - (unsigned char *) in) - 1;

	len = ((_bytes + 3) / 4) * 3;

	_out = (unsigned char *) out;

	_in = (unsigned char *) in;

	while (_bytes > 4) {

		*(_out++) = (unsigned char) (ascii[*_in] << 2 | ascii[_in[1]] >> 4);

		*(_out++) = (unsigned char) (ascii[_in[1]] << 4 | ascii[_in[2]] >> 2);

		*(_out++) = (unsigned char) (ascii[_in[2]] << 6 | ascii[_in[3]]);

		_in += 4;

		_bytes -= 4;

	}

	if (_bytes > 1) {

		*(_out++) = (unsigned char) (ascii[*_in] << 2 | ascii[_in[1]] >> 4);

	}

	if (_bytes > 2) {

		*(_out++) = (unsigned char) (ascii[_in[1]] << 4 | ascii[_in[2]] >> 2);

	}

	if (_bytes > 3) {

		*(_out++) = (unsigned char) (ascii[_in[2]] << 6 | ascii[_in[3]]);

	}

	*(_out++) = '\0';

	len -= (4 - _bytes) & 3;

	return len;

}

/**
 * 获取密码的KEY
 */
int get_password_key(char * password, char * key) {

	char * md5 = malloc(33);

	md5_encode(password, md5);

	md5[32] = '\0';

	base64_decode(md5, key);

	free(md5);

	return 24;

}

/**
 * 加密
 */
int encrypt(char *key, char *in, int inl, char *out) {

	unsigned char *_iv = malloc(32);

	do {

		RAND_bytes(_iv, 32);

	} while (strlen((char *) _iv) <= IV_SIZE);

	_iv[IV_SIZE] = '\0';

	unsigned char * iv = malloc(IV_SIZE + 1);

	memcpy(iv, _iv, IV_SIZE);

	free(_iv);

	unsigned char *cipher = malloc(inl + 1);

	int cipher_len = 0;

	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) malloc(sizeof(EVP_CIPHER_CTX));

	EVP_CIPHER_CTX_init(ctx);

	EVP_CIPHER_CTX_set_padding(ctx, EVP_CIPH_NO_PADDING);

	EVP_EncryptInit(ctx, EVP_aes_192_cfb128(), (unsigned char *) key, iv);

	EVP_EncryptUpdate(ctx, cipher, &cipher_len, (unsigned char *) in, inl);

	if (cipher_len != inl) {

		free(iv);

		free(cipher);

		return -1;

	}

	cipher[inl] = '\0';

	memcpy(out, iv, IV_SIZE);

	memcpy(&out[IV_SIZE], cipher, inl);

	free(iv);

	free(cipher);

	EVP_CIPHER_CTX_cleanup(ctx);

	return IV_SIZE + inl;

}

/**
 * 加密网络数据
 */
int encrypt_net(char *key, char *in, int in_len, char *out) {

	int cipher_len = in_len + IV_SIZE;

	char *cipher = malloc(cipher_len + 1);

	if (encrypt(key, in, in_len, cipher) == -1) {

		free(cipher);

		return -1;

	}

	cipher[cipher_len] = '\0';

	srand(time(NULL));

	int noisel = (cipher_len < NOISE_MAX / 2) ? rand() % NOISE_MAX : 0;

	unsigned char *noise = malloc(noisel + 1);

	RAND_bytes(noise, noisel);

	noisel = strlen((char *) noise);

	noise[noisel] = '\0';

	char *size = malloc(SIZE_SIZE + 1);

	sprintf(size, "%08d,%05d", cipher_len, noisel);

	size[SIZE_SIZE] = '\0';

	int size_cipher_len = SIZE_SIZE + IV_SIZE;

	char *size_cipher = malloc(size_cipher_len + 1);

	if (encrypt(key, size, SIZE_SIZE, size_cipher) == -1) {

		free(cipher);

		free(size_cipher);

		free(noise);

		free(size);
        
        return -1;

	}

	size_cipher[size_cipher_len] = '\0';

	int outl = size_cipher_len + cipher_len + noisel;

	memcpy(out, size_cipher, size_cipher_len);

	memcpy(&out[size_cipher_len], cipher, cipher_len);

	if (noisel > 0) {

		memcpy(&out[size_cipher_len + cipher_len], noise, noisel);

	}

	free(cipher);

	free(size_cipher);

	free(noise);

	free(size);

	return outl;

}

/**
 * 解密
 */
int decrypt(char *key, char *in, int inl, char *out) {

	int cipher_len = inl - IV_SIZE;

	unsigned char *iv = malloc(IV_SIZE + 1);

	unsigned char *cipher = malloc(cipher_len + 1);

	memcpy(iv, in, IV_SIZE);

	memcpy(cipher, &in[IV_SIZE], cipher_len);

	iv[IV_SIZE] = '\0';

	cipher[cipher_len] = '\0';

	int outl = 0;

	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) malloc(sizeof(EVP_CIPHER_CTX));

	EVP_CIPHER_CTX_init(ctx);

	EVP_CIPHER_CTX_set_padding(ctx, EVP_CIPH_NO_PADDING);

	EVP_DecryptInit(ctx, EVP_aes_192_cfb128(), (unsigned char *) key, iv);

	EVP_DecryptUpdate(ctx, (unsigned char *) out, &outl, cipher, cipher_len);

	free(iv);

	free(cipher);

	EVP_CIPHER_CTX_cleanup(ctx);

	if (cipher_len != outl) {

		return -1;

	}

	return cipher_len;

}

