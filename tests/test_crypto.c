/* The crypto suite: every primitive against its RFC's published vectors.
 * Host only. `python3 build.py test` builds and runs it. */
#include <stdio.h>
#include <string.h>
#include "crypto.h"

static int checks, failed;

static void hex(uint8_t *out, const char *s)
{
  while (*s) {
    unsigned hi = *s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10; s++;
    unsigned lo = *s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10; s++;
    *out++ = (uint8_t)(hi << 4 | lo);
  }
}

static void check(const char *name, const uint8_t *got, const char *want_hex, size_t n)
{
  uint8_t want[128];
  size_t i;
  hex(want, want_hex);
  checks++;
  if (memcmp(got, want, n) == 0) { printf("  ok   %s\n", name); return; }
  failed++;
  printf("  FAIL %s\n       got  ", name);
  for (i = 0; i < n; i++) printf("%02x", got[i]);
  printf("\n       want %s\n", want_hex);
}

static void check_int(const char *name, int got, int want)
{
  checks++;
  if (got == want) printf("  ok   %s\n", name);
  else { failed++; printf("  FAIL %s: got %d, want %d\n", name, got, want); }
}

int main(void)
{
  uint8_t out[64], key[32], nonce[12], pk[32], sig[64], msg[64], a[32], b[32];
  size_t i;

  /* SHA-256, FIPS 180-4 examples */
  sha256((const uint8_t *)"abc", 3, out);
  check("sha256 abc", out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);
  sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, out);
  check("sha256 two blocks", out, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 32);
  {
    sha256_ctx c; uint8_t m[1000];
    memset(m, 'a', sizeof m);
    sha256_init(&c);
    for (i = 0; i < 1000; i++) sha256_update(&c, m, sizeof m);
    sha256_final(&c, out);
    check("sha256 one million a", out, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 32);
  }

  /* SHA-512, FIPS 180-4 examples */
  {
    sha512_ctx c;
    sha512_init(&c); sha512_update(&c, (const uint8_t *)"abc", 3); sha512_final(&c, out);
    check("sha512 abc", out, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 64);
    sha512_init(&c);
    sha512_update(&c, (const uint8_t *)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112);
    sha512_final(&c, out);
    check("sha512 two blocks", out, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", 64);
  }

  /* ChaCha20, RFC 8439 2.3.2 (block) and 2.4.2 (encryption) */
  hex(key, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  hex(nonce, "000000090000004a00000000");
  chacha20_block(key, nonce, 1, out);
  check("chacha20 block", out, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", 64);
  {
    static const char *plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    uint8_t m[114];
    memcpy(m, plain, 114);
    hex(nonce, "000000000000004a00000000");
    chacha20_xor(key, nonce, 1, m, 114);
    check("chacha20 encrypt", m, "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d", 114);
  }
  /* the OpenSSH form: a 64-bit nonce and counter must give the same
   * keystream as the RFC form when the nonce's first 32 bits are zero */
  {
    uint8_t n8[8], o2[64];
    hex(nonce, "000000000000004a00000000");
    hex(n8, "0000004a00000000");
    chacha20_block(key, nonce, 7, out);
    chacha20_block64(key, n8, 7, o2);
    check_int("chacha20 64-bit form agrees", memcmp(out, o2, 64) == 0, 1);
  }

  /* Poly1305, RFC 8439 2.5.2 */
  hex(key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  poly1305(key, (const uint8_t *)"Cryptographic Forum Research Group", 34, out);
  check("poly1305 tag", out, "a8061dc1305136c6c22b8baf0c0127a9", 16);
  {
    poly1305_ctx c;                             /* the same, in odd pieces */
    poly1305_init(&c, key);
    poly1305_update(&c, (const uint8_t *)"Cryptographic Forum", 19);
    poly1305_update(&c, (const uint8_t *)" Research Group", 15);
    poly1305_final(&c, out);
    check("poly1305 streamed", out, "a8061dc1305136c6c22b8baf0c0127a9", 16);
  }
  check_int("field identities", (int)crypto_fe_selftest(), 0);

  /* X25519, RFC 7748 6.1 */
  hex(a, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");   /* Alice's private */
  x25519_base(out, a);
  check("x25519 Alice public", out, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32);
  hex(b, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");   /* Bob's private */
  x25519_base(out, b);
  check("x25519 Bob public", out, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", 32);
  hex(pk, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  x25519(out, a, pk);
  check("x25519 shared secret", out, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32);
  /* RFC 7748 5.2, the first vector */
  hex(a, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
  hex(pk, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
  x25519(out, a, pk);
  check("x25519 RFC 7748 5.2", out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", 32);

  /* Ed25519, RFC 8032 7.1, tests 1 to 3, plus a tampered message */
  hex(pk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  hex(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
  check_int("ed25519 test 1 (empty message)", ed25519_verify(sig, msg, 0, pk), 1);
  hex(pk, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
  hex(sig, "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
  msg[0] = 0x72;
  check_int("ed25519 test 2 (one byte)", ed25519_verify(sig, msg, 1, pk), 1);
  hex(pk, "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
  hex(sig, "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
  hex(msg, "af82");
  check_int("ed25519 test 3 (two bytes)", ed25519_verify(sig, msg, 2, pk), 1);
  msg[1] ^= 1;
  check_int("ed25519 rejects a changed message", ed25519_verify(sig, msg, 2, pk), 0);
  msg[1] ^= 1; sig[10] ^= 1;
  check_int("ed25519 rejects a changed signature", ed25519_verify(sig, msg, 2, pk), 0);

  /* Ed25519 signing, RFC 8032 7.1 tests 1 to 3 from their seeds */
  hex(a, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  ed25519_keypair(pk, a);
  check("ed25519 keypair test 1", pk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 32);
  ed25519_sign(sig, msg, 0, a, pk);
  check("ed25519 sign test 1 (empty message)", sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 64);
  hex(a, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
  ed25519_keypair(pk, a);
  check("ed25519 keypair test 2", pk, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", 32);
  msg[0] = 0x72;
  ed25519_sign(sig, msg, 1, a, pk);
  check("ed25519 sign test 2 (one byte)", sig, "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", 64);
  hex(a, "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
  ed25519_keypair(pk, a);
  check("ed25519 keypair test 3", pk, "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", 32);
  hex(msg, "af82");
  ed25519_sign(sig, msg, 2, a, pk);
  check("ed25519 sign test 3 (two bytes)", sig, "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", 64);
  check_int("ed25519 sign test 3 verifies", ed25519_verify(sig, msg, 2, pk), 1);

  printf("\n%d checks, %d failed\n", checks, failed);
  return failed ? 1 : 0;
}
