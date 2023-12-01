/* 
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 * 
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#ifndef __KECCAK_256_H__
#define __KECCAK_256_H__

#include <stddef.h>
#include <stdint.h>

#define IOTEX_HASH_LEN			32
#define IOTEX_BLOCK_SIZE		200 - IOTEX_HASH_LEN * 2
#define IOTEX_NUM_ROUNDS		24

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Computes the Keccak-256 hash of a sequence of bytes. The hash value is 32 bytes long.
 * Provides just one static method.
 */
void keccak256_getHash(const uint8_t *msg, size_t len, uint8_t *hashResult);


//class Keccak256 final {
	
//	public: static constexpr int HASH_LEN = 32;
//	private: static constexpr int BLOCK_SIZE = 200 - HASH_LEN * 2;
//	private: static constexpr int NUM_ROUNDS = 24;
	
	
//	public: static void getHash(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[HASH_LEN]);
	
	
//	private: static void absorb(std::uint64_t state[5][5]);
	
	
	// Requires 0 <= i <= 63
//	private: static std::uint64_t rotl64(std::uint64_t x, int i);
	
	
//	Keccak256() = delete;  // Not instantiable
	
	
//	private: static const unsigned char ROTATION[5][5];
	
//};

#ifdef __cplusplus
}
#endif

#endif /* __KECCAK_256_H__ */