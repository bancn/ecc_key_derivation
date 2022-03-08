
#include "utils.h"
#include "ecc.h"

int main() {

//    GenerateECCKey();
//

    mbedtls_mpi privKey;
    mbedtls_ecp_point newPubKey, oldPubKey;
    mbedtls_ecp_group grp;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&privKey);
    mbedtls_ecp_point_init(&newPubKey);
    mbedtls_ecp_point_init(&oldPubKey);
    int result  = mbedtls_ecp_group_load(&grp, 57);
    printf("result = %d\r\n", result);
    printf("result = 0x%x\r\n", result);
    printf("%c%04X\r\n", (result<0) ? '-' : ' ', (result<0) ?-result : result);

    return 0;
}
