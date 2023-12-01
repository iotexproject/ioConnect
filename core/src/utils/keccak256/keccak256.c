/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

//#include <cassert>
#include "include/utils/keccak256/keccak256.h"

// Static initializers
const unsigned char keccak256_ROTATION[5][5] = {
	{ 0, 36,  3, 41, 18},
	{ 1, 44, 10, 45,  2},
	{62,  6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39,  8, 14},
};

static uint64_t keccak256_rotl64(uint64_t x, int i) {

	return ((0U + x) << i) | (x >> ((64 - i) & 63));

}

static void keccak256_absorb(uint64_t state[5][5]) {

	uint64_t (*a)[5] = state;
	uint8_t r = 1;  // LFSR
	for (int i = 0; i < IOTEX_NUM_ROUNDS; i++) {
		// Theta step
		uint64_t c[5] = {};
		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++)
				c[x] ^= a[x][y];
		}
		for (int x = 0; x < 5; x++) {
			uint64_t d = c[(x + 4) % 5] ^ keccak256_rotl64(c[(x + 1) % 5], 1);
			for (int y = 0; y < 5; y++)
				a[x][y] ^= d;
		}
		
		// Rho and pi steps
		uint64_t b[5][5];
		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++)
				b[y][(x * 2 + y * 3) % 5] = keccak256_rotl64(a[x][y], keccak256_ROTATION[x][y]);
		}
		
		// Chi step
		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++)
				a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]);
		}
		
		// Iota step
		for (int j = 0; j < 7; j++) {
			a[0][0] ^= (uint64_t)(r & 1) << ((1 << j) - 1);
			r = (uint8_t)((r << 1) ^ ((r >> 7) * 0x171));
		}
	}
}

void keccak256_getHash(const uint8_t *msg, size_t len, uint8_t *hashResult) {

	if( NULL == msg || 0 == len || NULL == hashResult )
		return;
	
	uint64_t state[5][5] = {};
	
	// XOR each message byte into the state, and absorb full blocks
	int blockOff = 0;
	for (size_t i = 0; i < len; i++) {
		int j = blockOff >> 3;
		state[j % 5][j / 5] ^= (uint64_t)(msg[i]) << ((blockOff & 7) << 3);
		blockOff++;
		if (blockOff == IOTEX_BLOCK_SIZE) {
			keccak256_absorb(state);
			blockOff = 0;
		}
	}
	
	// Final block and padding
	{
		int i = blockOff >> 3;
		state[i % 5][i / 5] ^= UINT64_C(0x01) << ((blockOff & 7) << 3);
		blockOff = IOTEX_BLOCK_SIZE - 1;
		int j = blockOff >> 3;
		state[j % 5][j / 5] ^= UINT64_C(0x80) << ((blockOff & 7) << 3);
		keccak256_absorb(state);
	}
	
	// Uint64 array to bytes in little endian
	for (int i = 0; i < IOTEX_HASH_LEN; i++) {
		int j = i >> 3;
		hashResult[i] = (uint8_t)(state[j % 5][j / 5] >> ((i & 7) << 3));
	}
}







