/*
 * elgamal_tool.c
 *
 * EC ElGamal commitment (commit & open/verify) CLI using OpenSSL.
 *
 * Usage:
 *   # generate keypair (recipient)
 *   ./elgamal_tool genkey <priv_hex_out> <pub_hex_out> [nid]
 *
 *   # commit: produce R,S (hex). Optionally save r to a file.
 *   ./elgamal_tool commit <recipient_pub_hex> <message_int> [r_out_hex_file]
 *
 *   # verify (open): verify R,S with announced m and r
 *   ./elgamal_tool verify <recipient_pub_hex> <R_hex> <S_hex> <message_int> <r_hex>
 *
 * Notes:
 *  - Message integer m must be in range [0, order-1].
 *  - All points are encoded in uncompressed octet hex.
 *  - Private scalars are hex big-endian.
 *
 * Compile:
 *   gcc -O2 -Wall elgamal_tool.c -o elgamal_tool -lcrypto
 */

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRY_OR_EXIT(cond, msg) if (!(cond)) { fprintf(stderr, "ERROR: %s\n", msg); ERR_print_errors_fp(stderr); exit(1); }

/* Helpers --------------------------------------------------------------- */

static void hex_to_bin(const char *hex, unsigned char **out, size_t *out_len) {
    size_t len = strlen(hex);
    TRY_OR_EXIT(len % 2 == 0, "hex string length must be even");
    *out_len = len / 2;
    *out = OPENSSL_malloc(*out_len);
    TRY_OR_EXIT(*out, "malloc failed");
    for (size_t i = 0; i < *out_len; ++i) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) { OPENSSL_free(*out); *out = NULL; *out_len = 0; return; }
        (*out)[i] = (unsigned char)byte;
    }
}

static char *bin_to_hex(const unsigned char *bin, size_t bin_len) {
    char *hex = OPENSSL_malloc(bin_len * 2 + 1);
    TRY_OR_EXIT(hex, "malloc failed");
    for (size_t i = 0; i < bin_len; ++i) sprintf(hex + 2*i, "%02x", bin[i]);
    hex[bin_len*2] = '\0';
    return hex;
}

static char *point_to_hex(const EC_GROUP *grp, const EC_POINT *pt) {
    BN_CTX *ctx = BN_CTX_new();
    TRY_OR_EXIT(ctx, "BN_CTX_new");
    size_t len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, ctx);
    unsigned char *buf = OPENSSL_malloc(len);
    TRY_OR_EXIT(buf, "malloc");
    EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, buf, len, ctx);
    char *hex = bin_to_hex(buf, len);
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    return hex;
}

static EC_POINT *hex_to_point(const EC_GROUP *grp, const char *hex) {
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    hex_to_bin(hex, &buf, &buf_len);
    TRY_OR_EXIT(buf, "invalid hex");
    BN_CTX *ctx = BN_CTX_new();
    TRY_OR_EXIT(ctx, "BN_CTX_new");
    EC_POINT *pt = EC_POINT_new(grp);
    TRY_OR_EXIT(pt, "EC_POINT_new");
    int ok = EC_POINT_oct2point(grp, pt, buf, buf_len, ctx);
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    if (!ok) { EC_POINT_free(pt); return NULL; }
    return pt;
}

static char *bn_to_hex(const BIGNUM *bn) {
    char *hex = BN_bn2hex(bn);
    return hex; /* allocated by OpenSSL; free with OPENSSL_free or OPENSSL_hexstr_free? BN_bn2hex uses OPENSSL_malloc, free with OPENSSL_free */
}

static BIGNUM *hex_to_bn(const char *hex) {
    BIGNUM *bn = NULL;
    if (BN_hex2bn(&bn, hex) == 0) return NULL;
    return bn;
}

/* EC utilities --------------------------------------------------------- */

static EC_GROUP *group_by_nid(int nid) {
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    TRY_OR_EXIT(g, "EC_GROUP_new_by_curve_name failed");
    return g;
}

/* generate keypair: returns priv (BIGNUM) and pub (EC_POINT) */
static int ec_generate_keypair(const EC_GROUP *group, BIGNUM **out_priv, EC_POINT **out_pub) {
    const BIGNUM *order = EC_GROUP_get0_order(group);
    TRY_OR_EXIT(order, "get order failed");
    BIGNUM *priv = BN_new();
    TRY_OR_EXIT(priv, "BN_new");
    /* random in [1, order-1] */
    do {
        TRY_OR_EXIT(BN_rand_range(priv, order) == 1, "BN_rand_range failed");
    } while (BN_is_zero(priv));
    BN_CTX *ctx = BN_CTX_new();
    TRY_OR_EXIT(ctx, "BN_CTX_new");
    EC_POINT *pub = EC_POINT_new(group);
    TRY_OR_EXIT(pub, "EC_POINT_new");
    TRY_OR_EXIT(EC_POINT_mul(group, pub, priv, NULL, NULL, ctx) == 1, "EC_POINT_mul pub");
    BN_CTX_free(ctx);
    *out_priv = priv;
    *out_pub = pub;
    return 1;
}

/* random scalar r in [1, order-1] */
static BIGNUM *random_scalar(const EC_GROUP *group) {
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BIGNUM *r = BN_new();
    TRY_OR_EXIT(r, "BN_new");
    do {
        TRY_OR_EXIT(BN_rand_range(r, order) == 1, "BN_rand_range failed");
    } while (BN_is_zero(r));
    return r;
}

/* compute m*G where m is provided as BIGNUM (message scalar) */
static EC_POINT *scalar_mul_base(const EC_GROUP *group, const BIGNUM *m) {
    BN_CTX *ctx = BN_CTX_new();
    TRY_OR_EXIT(ctx, "BN_CTX_new");
    EC_POINT *pt = EC_POINT_new(group);
    TRY_OR_EXIT(pt, "EC_POINT_new");
    TRY_OR_EXIT(EC_POINT_mul(group, pt, m, NULL, NULL, ctx) == 1, "EC_POINT_mul base");
    BN_CTX_free(ctx);
    return pt;
}

/* ---------- ElGamal commit & verify ---------------------------------- */

/* commit:
 *   Given recipient public key Y and message integer m (BIGNUM),
 *   choose r random and compute:
 *     R = r*G
 *     S = r*Y + m*G
 *   returns R, S, r
 */
static int elgamal_commit(const EC_GROUP *group, const EC_POINT *Y,
                          const BIGNUM *m_scalar,
                          EC_POINT **out_R, EC_POINT **out_S, BIGNUM **out_r) {
    BN_CTX *ctx = BN_CTX_new();
    TRY_OR_EXIT(ctx, "BN_CTX_new");
    const BIGNUM *order = EC_GROUP_get0_order(group);
    TRY_OR_EXIT(order, "order");

    /* check m < order */
    if (BN_cmp(m_scalar, order) >= 0 || BN_is_negative(m_scalar)) {
        BN_CTX_free(ctx);
        return 0;
    }

    BIGNUM *r = random_scalar(group);

    EC_POINT *R = EC_POINT_new(group);
    EC_POINT *rY = EC_POINT_new(group);
    EC_POINT *mG = EC_POINT_new(group);
    EC_POINT *S = EC_POINT_new(group);
    TRY_OR_EXIT(R && rY && mG && S, "EC_POINT_new failed");

    /* R = r*G */
    TRY_OR_EXIT(EC_POINT_mul(group, R, r, NULL, NULL, ctx) == 1, "EC_POINT_mul r*G failed");

    /* rY = r * Y */
    TRY_OR_EXIT(EC_POINT_mul(group, rY, NULL, Y, r, ctx) == 1, "EC_POINT_mul r*Y failed");

    /* mG = m * G */
    TRY_OR_EXIT(EC_POINT_mul(group, mG, m_scalar, NULL, NULL, ctx) == 1, "EC_POINT_mul m*G failed");

    /* S = rY + mG */
    TRY_OR_EXIT(EC_POINT_add(group, S, rY, mG, ctx) == 1, "EC_POINT_add failed");

    BN_free(rY ? NULL : NULL); /* no-op to silence static analyzer */

    BN_CTX_free(ctx);
    *out_R = R;
    *out_S = S;
    *out_r = r;
    return 1;
}

/* verify opening:
 *   Given recipient pub Y, commitment R,S, announced m and r,
 *   check R == r*G and S == r*Y + m*G
 */
static int elgamal_verify(const EC_GROUP *group, const EC_POINT *Y,
                          const EC_POINT *R, const EC_POINT *S,
                          const BIGNUM *m_scalar, const BIGNUM *r) {
    BN_CTX *ctx = BN_CTX_new();
    TRY_OR_EXIT(ctx, "BN_CTX_new");
    const BIGNUM *order = EC_GROUP_get0_order(group);
    TRY_OR_EXIT(order, "order");

    if (BN_cmp(m_scalar, order) >= 0 || BN_is_negative(m_scalar)) {
        BN_CTX_free(ctx);
        return 0;
    }
    if (BN_cmp(r, order) >= 0 || BN_is_negative(r)) {
        BN_CTX_free(ctx);
        return 0;
    }

    /* compute r*G and compare to R */
    EC_POINT *rG = EC_POINT_new(group);
    TRY_OR_EXIT(rG, "EC_POINT_new");
    TRY_OR_EXIT(EC_POINT_mul(group, rG, r, NULL, NULL, ctx) == 1, "EC_POINT_mul rG failed");
    if (EC_POINT_cmp(group, rG, R, ctx) != 0) { EC_POINT_free(rG); BN_CTX_free(ctx); return 0; }
    EC_POINT_free(rG);

    /* compute rY + mG and compare to S */
    EC_POINT *rY = EC_POINT_new(group);
    EC_POINT *mG = EC_POINT_new(group);
    EC_POINT *rhs = EC_POINT_new(group);
    TRY_OR_EXIT(rY && mG && rhs, "EC_POINT_new failed");
    TRY_OR_EXIT(EC_POINT_mul(group, rY, NULL, Y, r, ctx) == 1, "EC_POINT_mul rY failed");
    TRY_OR_EXIT(EC_POINT_mul(group, mG, m_scalar, NULL, NULL, ctx) == 1, "EC_POINT_mul mG failed");
    TRY_OR_EXIT(EC_POINT_add(group, rhs, rY, mG, ctx) == 1, "EC_POINT_add failed");

    int ok = (EC_POINT_cmp(group, rhs, S, ctx) == 0);

    EC_POINT_free(rY); EC_POINT_free(mG); EC_POINT_free(rhs);
    BN_CTX_free(ctx);
    return ok;
}

/* ---------- main & CLI ----------------------------------------------- */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s genkey <priv_hex_out> <pub_hex_out> [nid]\n"
        "  %s commit <recipient_pub_hex> <message_int> [r_out_hex_file]\n"
        "  %s verify <recipient_pub_hex> <R_hex> <S_hex> <message_int> <r_hex>\n"
        "\n"
        "Notes:\n"
        "  - Points and scalars are hex (uncompressed point for R and S).\n"
        "  - message_int must be a non-negative integer < group order.\n"
        "  - For genkey, nid defaults to 415 (prime256v1). Use NID numbers if you want other curves.\n",
        prog, prog, prog);
}

int main(int argc, char **argv) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (argc < 2) { print_usage(argv[0]); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "genkey") == 0) {
        if (argc < 4) { print_usage(argv[0]); return 1; }
        const char *priv_out = argv[2];
        const char *pub_out = argv[3];
        int nid = (argc >= 5) ? atoi(argv[4]) : NID_X9_62_prime256v1;
        EC_GROUP *group = group_by_nid(nid);

        BIGNUM *priv = NULL;
        EC_POINT *pub = NULL;
        ec_generate_keypair(group, &priv, &pub);

        /* write priv hex */
        char *priv_hex = bn_to_hex(priv);
        FILE *fpriv = fopen(priv_out, "w");
        TRY_OR_EXIT(fpriv, "open priv_out");
        fprintf(fpriv, "%s\n", priv_hex);
        fclose(fpriv);
        OPENSSL_free(priv_hex);

        /* write pub hex */
        char *pub_hex = point_to_hex(group, pub);
        FILE *fpub = fopen(pub_out, "w");
        TRY_OR_EXIT(fpub, "open pub_out");
        fprintf(fpub, "%s\n", pub_hex);
        fclose(fpub);
        OPENSSL_free(pub_hex);

        BN_free(priv);
        EC_POINT_free(pub);
        EC_GROUP_free(group);
        printf("Keypair generated to %s (priv) and %s (pub)\n", priv_out, pub_out);
        return 0;
    }

    if (strcmp(cmd, "commit") == 0) {
        if (argc < 4) { print_usage(argv[0]); return 1; }
        const char *pub_hex = argv[2];
        const char *m_str = argv[3];
        const char *r_out_file = (argc >= 5) ? argv[4] : NULL;

        EC_GROUP *group = group_by_nid(NID_X9_62_prime256v1);
        EC_POINT *Y = hex_to_point(group, pub_hex);
        TRY_OR_EXIT(Y, "invalid recipient pub hex");

        /* parse m as BIGNUM decimal */
        BIGNUM *m = BN_new();
        TRY_OR_EXIT(m && BN_dec2bn(&m, m_str), "invalid message integer");

        /* commit */
        EC_POINT *R = NULL, *S = NULL;
        BIGNUM *r = NULL;
        int ok = elgamal_commit(group, Y, m, &R, &S, &r);
        TRY_OR_EXIT(ok, "commit failed (maybe m out of range)");

        char *R_hex = point_to_hex(group, R);
        char *S_hex = point_to_hex(group, S);
        char *r_hex = bn_to_hex(r);

        printf("R=%s\n", R_hex);
        printf("S=%s\n", S_hex);
        if (r_out_file) {
            FILE *fr = fopen(r_out_file, "w");
            TRY_OR_EXIT(fr, "open r_out_file failed");
            fprintf(fr, "%s\n", r_hex);
            fclose(fr);
            printf("Randomness r written to %s (keep it secret until opening)\n", r_out_file);
        } else {
            printf("Keep r secret. To open later reveal m and r.\n");
            printf("r=%s\n", r_hex);
        }

        OPENSSL_free(R_hex); OPENSSL_free(S_hex); OPENSSL_free(r_hex);
        BN_free(m);
        BN_free(r);
        EC_POINT_free(R); EC_POINT_free(S);
        EC_POINT_free(Y);
        EC_GROUP_free(group);
        return 0;
    }

    if (strcmp(cmd, "verify") == 0) {
        if (argc < 7) { print_usage(argv[0]); return 1; }
        const char *pub_hex = argv[2];
        const char *R_hex = argv[3];
        const char *S_hex = argv[4];
        const char *m_str = argv[5];
        const char *r_hex_str = argv[6];

        EC_GROUP *group = group_by_nid(NID_X9_62_prime256v1);
        EC_POINT *Y = hex_to_point(group, pub_hex);
        EC_POINT *R = hex_to_point(group, R_hex);
        EC_POINT *S = hex_to_point(group, S_hex);
        TRY_OR_EXIT(Y && R && S, "invalid hex for Y, R, or S");

        BIGNUM *m = BN_new();
        TRY_OR_EXIT(m && BN_dec2bn(&m, m_str), "invalid message integer decimal");

        BIGNUM *r = hex_to_bn(r_hex_str);
        TRY_OR_EXIT(r, "invalid r hex");

        int ok = elgamal_verify(group, Y, R, S, m, r);
        printf("Verification: %s\n", ok ? "OK" : "FAIL");

        BN_free(m); BN_free(r);
        EC_POINT_free(R); EC_POINT_free(S); EC_POINT_free(Y);
        EC_GROUP_free(group);
        return (ok ? 0 : 2);
    }

    print_usage(argv[0]);
    return 1;
}

