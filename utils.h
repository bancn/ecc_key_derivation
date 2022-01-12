//
// Created by Bancn on 2022/1/11.
//

#ifndef ECC_UTILS_H
#define ECC_UTILS_H

#include <stdint.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

#define CHECK_RESULT(ret)  \
    if (ret != 0) {            \
        break;                 \
    }


void dump_buf(char *info, uint8_t *buf, uint32_t len);
void print_buf(char *info, uint8_t *buf, uint32_t len);
void GetECDHKey();
void CheckKey();
uint32_t GeneratePubKeyByPrivKey(mbedtls_mpi *privKey, mbedtls_ecp_point *pubKey);
void testVerifyKey();
#endif //ECC_UTILS_H
