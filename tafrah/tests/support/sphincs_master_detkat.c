#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"

static uint8_t g_optrand[SPX_N];

int randombytes(uint8_t *out, size_t outlen) {
    if (outlen != SPX_N) {
        return -1;
    }
    memcpy(out, g_optrand, SPX_N);
    return 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int decode_hex_arg(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void print_hex_line(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    uint8_t seed[CRYPTO_SEEDBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t *msg;
    uint8_t *sig;
    size_t siglen = 0;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <seed> <optrand> <msg>\n", argv[0]);
        return 2;
    }

    if (decode_hex_arg(argv[1], seed, sizeof(seed)) != 0) {
        fprintf(stderr, "invalid seed hex\n");
        return 3;
    }
    if (decode_hex_arg(argv[2], g_optrand, sizeof(g_optrand)) != 0) {
        fprintf(stderr, "invalid optrand hex\n");
        return 4;
    }

    msg = malloc(strlen(argv[3]) / 2);
    if (msg == NULL) {
        fprintf(stderr, "malloc failed\n");
        return 5;
    }
    if (decode_hex_arg(argv[3], msg, strlen(argv[3]) / 2) != 0) {
        fprintf(stderr, "invalid msg hex\n");
        free(msg);
        return 6;
    }

    sig = malloc(CRYPTO_BYTES);
    if (sig == NULL) {
        fprintf(stderr, "malloc failed\n");
        free(msg);
        return 7;
    }

    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        fprintf(stderr, "crypto_sign_seed_keypair failed\n");
        free(sig);
        free(msg);
        return 8;
    }

    if (crypto_sign_signature(sig, &siglen, msg, strlen(argv[3]) / 2, sk) != 0) {
        fprintf(stderr, "crypto_sign_signature failed\n");
        free(sig);
        free(msg);
        return 9;
    }

    print_hex_line(pk, sizeof(pk));
    print_hex_line(sk, sizeof(sk));
    print_hex_line(sig, siglen);

    free(sig);
    free(msg);
    return 0;
}
