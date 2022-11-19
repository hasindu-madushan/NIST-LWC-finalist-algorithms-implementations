// 07 Nov 2022
#include "../../utils/hex_utils.h"
#include <stdio.h>


void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
}

uint8_t decrypt(uint8_t *plain_text, uint8_t *tag, uint8_t *cipher_text, uint32_t cipher_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    return 0;
}

int main() 
{
    /* Count = 7
       Key = 000102030405060708090A0B0C0D0E0F
       Nonce = 000102030405060708090A0B0C0D0E0F
       PT = 
       AD = 000102030405
       CT = CE5473EF021AD7853E66C69C56F57167 */


    printf("done!\n");
    return 0;
}
