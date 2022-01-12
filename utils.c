//
// Created by Bancn on 2022/1/11.
//
#include "utils.h"
#include <stdio.h>
#include <mbedtls/platform.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include <mbedtls/ecdh.h>
#include <stdbool.h>

void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; ++i) {
        mbedtls_printf("%s%02X%s", i%16 == 0 ? "\n    " : " ",
                       buf[i], i == len - 1 ? "\n" : "");
    }
}

void GetECCKey()
{
    int ret = 0;
    size_t olen;
    char buf[65];
    mbedtls_ecp_group grp;
    mbedtls_mpi cli_secret, srv_secret;
    mbedtls_mpi cli_pri, srv_pri;
    mbedtls_ecp_point cli_pub, srv_pub;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t *pers = "simple_ecdh";

    mbedtls_mpi_init(&cli_pri); //
    mbedtls_mpi_init(&srv_pri);
    mbedtls_mpi_init(&cli_secret);
    mbedtls_mpi_init(&srv_secret);
    mbedtls_ecp_group_init(&grp); //初始化椭圆曲线群结构体
    mbedtls_ecp_point_init(&cli_pub); //初始化椭圆曲线点结构体 cli
    mbedtls_ecp_point_init(&srv_pub);//初始化椭圆曲线点结构体 srv

    mbedtls_entropy_init(&entropy); //初始化熵结构体
    mbedtls_ctr_drbg_init(&ctr_drbg);//初始化随机数结构体

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const uint8_t *) pers, strlen(pers));
    mbedtls_printf("\n  . setup rng ... ok\n");

    //加载椭圆曲线，选择SECP256R1
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_printf("\n  . select ecp group SECP256R1 ... ok\n");
    //cli生成公开参数
    ret = mbedtls_ecdh_gen_public(&grp,    //椭圆曲线结构体
                                  &cli_pri,//输出cli私密参数d
                                  &cli_pub,//输出cli公开参数Q
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&grp, &cli_pub, //把cli的公开参数到处到buf中
                                   MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, sizeof(buf));
    dump_buf("  1. ecdh client generate public parameter:", buf, olen);

    //srv生成公开参数
    ret = mbedtls_ecdh_gen_public(&grp,    //椭圆曲线结构体
                                  &srv_pri,//输出srv私密参数d
                                  &srv_pub,//输出srv公开参数Q
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    mbedtls_ecp_point_write_binary(&grp, &srv_pub, //把srv的公开参数导出到buf中
                                   MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, sizeof(buf));
    dump_buf("  2. ecdh server generate public parameter:", buf, olen);
    //cli计算共享密钥
    ret = mbedtls_ecdh_compute_shared(&grp,    //椭圆曲线结构体
                                      &cli_secret, //cli计算出的共享密钥
                                      &srv_pub, //输入srv公开参数Q
                                      &cli_pri, //输入cli本身的私密参数d
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    //把cli计算出的共享密钥导出buf中
    mbedtls_mpi_write_binary(&cli_secret, buf, mbedtls_mpi_size(&cli_secret));
    dump_buf("  3. ecdh client generate secret:", buf, mbedtls_mpi_size(&cli_secret));

    //srv计算共享密钥
    ret = mbedtls_ecdh_compute_shared(&grp,   //椭圆曲线结构体
                                      &srv_secret, //srv计算出的共享密钥
                                      &cli_pub, //输入cli公开参数Q
                                      &srv_pri, //输入srv本身的私密参数d
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    assert_exit(ret == 0, ret);
    //把srv计算出的共享密钥导出buf中
    mbedtls_mpi_write_binary(&srv_secret, buf, mbedtls_mpi_size(&srv_secret));
    dump_buf("  4. ecdh server generate secret:", buf, mbedtls_mpi_size(&srv_secret));

    //比较2个大数是否相等
    ret = mbedtls_mpi_cmp_mpi(&cli_secret, &srv_secret);
    assert_exit(ret == 0, ret);
    mbedtls_printf("  5. ecdh checking secrets ... ok\n");

    cleanup:
    mbedtls_mpi_free(&cli_pri);
    mbedtls_mpi_free(&srv_pri);
    mbedtls_mpi_free(&cli_secret);
    mbedtls_mpi_free(&srv_secret);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&cli_pub);
    mbedtls_ecp_point_free(&srv_pub);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}


void CheckKey()
{
    uint8_t pubX[32] = {0x85, 0x3B, 0x70, 0x4F, 0x06, 0x6C, 0xDA, 0x0D, 0x10, 0x64, 0xDE, 0x34, 0x19, 0xE9, 0x7B, 0x8E,
                        0x27, 0x7F, 0x65, 0x95, 0x80, 0x0A, 0x0D, 0x43, 0xE3, 0x73, 0x61, 0x47, 0x2B, 0x48, 0x2B, 0xE3,};
    uint8_t pubY[32] = {0xD0, 0xDB, 0x4D, 0xFD, 0xB1, 0x4C, 0x8C, 0xEB, 0x7C, 0x93, 0x2B, 0xEC, 0x2A, 0xE2, 0x84, 0xD8,
                        0x4E, 0x12, 0x9E, 0x7E, 0xFD, 0xDB, 0x48, 0xAA, 0xAD, 0x91, 0x38, 0xBB, 0x98, 0xFA, 0xB2, 0x87};

    uint8_t pub[65]  = {0x04, 0x85, 0x3B, 0x70, 0x4F, 0x06, 0x6C, 0xDA, 0x0D, 0x10, 0x64, 0xDE, 0x34, 0x19, 0xE9, 0x7B,
                        0x8E, 0x27, 0x7F, 0x65, 0x95, 0x80, 0x0A, 0x0D, 0x43, 0xE3, 0x73, 0x61, 0x47, 0x2B, 0x48, 0x2B,
                        0xE3, 0xD0, 0xDB, 0x4D, 0xFD, 0xB1, 0x4C, 0x8C, 0xEB, 0x7C, 0x93, 0x2B, 0xEC, 0x2A, 0xE2, 0x84,
                        0xD8, 0x4E, 0x12, 0x9E, 0x7E, 0xFD, 0xDB, 0x48, 0xAA, 0xAD, 0x91, 0x38, 0xBB, 0x98, 0xFA, 0xB2,
                        0x87};
    uint8_t priv[32] = {0x41, 0x0B, 0x6C, 0x60, 0xB9, 0x3C, 0xF8, 0x3F, 0x0A, 0x08, 0xB6, 0xDE, 0xE1, 0xFC, 0x86, 0x62,
                        0x0E, 0x68, 0x21, 0x53, 0xE5, 0x52, 0xE7, 0xA9, 0x21, 0xB4, 0xD4, 0x19, 0xA9, 0x9C, 0x48, 0x46};

    uint32_t result;
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);

    do {
        result = mbedtls_ecp_group_load(&key.grp, MBEDTLS_ECP_DP_SECP256R1);
        CHECK_RESULT(result);

        result = mbedtls_mpi_read_binary(&key.d, priv, 32);
        CHECK_RESULT(result);

        result = mbedtls_ecp_point_read_binary(&key.grp, &key.Q, pub, 65);
        CHECK_RESULT(result);

        result = mbedtls_ecp_check_pub_priv(&key, &key);
    } while (false);

    mbedtls_ecp_keypair_free(&key);
}