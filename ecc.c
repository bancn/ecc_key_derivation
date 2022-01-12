//
// Created by Bancn on 2022/1/12.
//

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <stdbool.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include "ecc.h"
#include "utils.h"

void GenerateECCKey()
{
    int result;
    mbedtls_ecp_group grp;
    mbedtls_mpi cli_priv;
    mbedtls_ecp_point cli_pub;
    mbedtls_ecp_keypair keypair;


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t *pers = "tssTA";

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&cli_priv);
    mbedtls_ecp_point_init(&cli_pub);
    mbedtls_ecp_keypair_init(&keypair);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    uint8_t pri[100] = {0};
    uint8_t pub[100] = {0};
    size_t olen;
    do {

        result = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, &pers, strlen(pers));
        CHECK_RESULT(result);

        result = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        CHECK_RESULT(result);

        result = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &keypair, mbedtls_ctr_drbg_random, &ctr_drbg);
        CHECK_RESULT(result);

        result = mbedtls_mpi_write_binary(&keypair.d, pri, 32);
        CHECK_RESULT(result);
        print_buf("privkey:", pri, 32);


        result = mbedtls_ecp_point_write_binary(&keypair.grp, &keypair.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 100);
        CHECK_RESULT(result);
        print_buf("pubkey", pub, olen);

        result = mbedtls_ecp_check_pub_priv(&keypair, &keypair);
        CHECK_RESULT(result);
    } while (false);



}
