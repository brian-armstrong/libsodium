/*
version 20080912
D. J. Bernstein
Public domain.
*/

#include "api.h"

#include <x86intrin.h>

#define ROUNDS 20

typedef unsigned int uint32;

static uint32 rotate(uint32 u,int c)
{
  return (u << c) | (u >> (32 - c));
}

static uint32 load_littleendian(const unsigned char *x)
{
  return
      (uint32) (x[0]) \
  | (((uint32) (x[1])) << 8) \
  | (((uint32) (x[2])) << 16) \
  | (((uint32) (x[3])) << 24)
  ;
}

static void store_littleendian(unsigned char *x,uint32 u)
{
  x[0] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[3] = u;
}

/*
int crypto_core(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  uint32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  int i;

  j0 = x0 = load_littleendian(c + 0);
  j1 = x1 = load_littleendian(k + 0);
  j2 = x2 = load_littleendian(k + 4);
  j3 = x3 = load_littleendian(k + 8);
  j4 = x4 = load_littleendian(k + 12);
  j5 = x5 = load_littleendian(c + 4);
  j6 = x6 = load_littleendian(in + 0);
  j7 = x7 = load_littleendian(in + 4);
  j8 = x8 = load_littleendian(in + 8);
  j9 = x9 = load_littleendian(in + 12);
  j10 = x10 = load_littleendian(c + 8);
  j11 = x11 = load_littleendian(k + 16);
  j12 = x12 = load_littleendian(k + 20);
  j13 = x13 = load_littleendian(k + 24);
  j14 = x14 = load_littleendian(k + 28);
  j15 = x15 = load_littleendian(c + 12);

  for (i = ROUNDS;i > 0;i -= 2) {
     x4 ^= rotate( x0+x12, 7);
     x8 ^= rotate( x4+ x0, 9);
    x12 ^= rotate( x8+ x4,13);
     x0 ^= rotate(x12+ x8,18);
     x9 ^= rotate( x5+ x1, 7);
    x13 ^= rotate( x9+ x5, 9);
     x1 ^= rotate(x13+ x9,13);
     x5 ^= rotate( x1+x13,18);
    x14 ^= rotate(x10+ x6, 7);
     x2 ^= rotate(x14+x10, 9);
     x6 ^= rotate( x2+x14,13);
    x10 ^= rotate( x6+ x2,18);
     x3 ^= rotate(x15+x11, 7);
     x7 ^= rotate( x3+x15, 9);
    x11 ^= rotate( x7+ x3,13);
    x15 ^= rotate(x11+ x7,18);
     x1 ^= rotate( x0+ x3, 7);
     x2 ^= rotate( x1+ x0, 9);
     x3 ^= rotate( x2+ x1,13);
     x0 ^= rotate( x3+ x2,18);
     x6 ^= rotate( x5+ x4, 7);
     x7 ^= rotate( x6+ x5, 9);
     x4 ^= rotate( x7+ x6,13);
     x5 ^= rotate( x4+ x7,18);
    x11 ^= rotate(x10+ x9, 7);
     x8 ^= rotate(x11+x10, 9);
     x9 ^= rotate( x8+x11,13);
    x10 ^= rotate( x9+ x8,18);
    x12 ^= rotate(x15+x14, 7);
    x13 ^= rotate(x12+x15, 9);
    x14 ^= rotate(x13+x12,13);
    x15 ^= rotate(x14+x13,18);
  }

  x0 += j0;
  x1 += j1;
  x2 += j2;
  x3 += j3;
  x4 += j4;
  x5 += j5;
  x6 += j6;
  x7 += j7;
  x8 += j8;
  x9 += j9;
  x10 += j10;
  x11 += j11;
  x12 += j12;
  x13 += j13;
  x14 += j14;
  x15 += j15;

  store_littleendian(out + 0,x0);
  store_littleendian(out + 4,x1);
  store_littleendian(out + 8,x2);
  store_littleendian(out + 12,x3);
  store_littleendian(out + 16,x4);
  store_littleendian(out + 20,x5);
  store_littleendian(out + 24,x6);
  store_littleendian(out + 28,x7);
  store_littleendian(out + 32,x8);
  store_littleendian(out + 36,x9);
  store_littleendian(out + 40,x10);
  store_littleendian(out + 44,x11);
  store_littleendian(out + 48,x12);
  store_littleendian(out + 52,x13);
  store_littleendian(out + 56,x14);
  store_littleendian(out + 60,x15);

  return 0;
}
*/

int crypto_core(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
    int i;
    __m128i T0, T1, T2, T3, T4, T5, T6, T7, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    // T0 = [  x0 |  x5 | x10 | x15 ] (load c || load constants)
    // T1 = [  x1 |  x2 |  x3 |  x4 ] (load k)
    // T2 = [ x11 | x12 | x13 | x14 ] (load k + 16)
    // T3 = [  x6 |  x7 |  x8 |  x9 ] (load in)

    if (c == NULL) {
        T0 = _mm_set_epi32(0x6b206574, 0x79622d32, 0x3320646e, 0x61707865);
    } else {
        T0 = _mm_load_si128((const __m128i *)(c));
    }

    T1 = _mm_load_si128((const __m128i *)(k));
    T2 = _mm_load_si128((const __m128i *)(k) + 1);
    T3 = _mm_load_si128((const __m128i *)(in));

    // T0 = [  x0 |  x5 | x10 | x15 ] (copy t0)
    // T1 = [  x4 |  x1 |  x2 |  x3 ] (shuffle t1)
    // T2 = [ x12 | x13 | x14 | x11 ] (shuffle t2)
    // T3 = [  x8 |  x9 |  x6 |  x7 ] (shuffle t3)

    T5 = _mm_set_epi32(0x0b0a0908, 0x07060504, 0x03020100, 0x0f0e0d0c);
    T6 = _mm_set_epi32(0x03020100, 0x0f0e0d0c, 0x0b0a0908, 0x07060504);
    T7 = _mm_set_epi32(0x07060504, 0x03020100, 0x0f0e0d0c, 0x0b0a0908);

    T1 = _mm_shuffle_epi8(T1, T5);
    T2 = _mm_shuffle_epi8(T2, T6);
    T3 = _mm_shuffle_epi8(T3, T7);

    // X <- T

    X0 = T0;
    X1 = T1;
    X2 = T2;
    X3 = T3;

    // X0 = [  x0 |  x5 | x10 | x15 ] (nop)
    // X1 = [  x4 |  x9 |  x2 |  x3 ] (select t3[1])
    // X2 = [ x12 |  x1 | x14 | x11 ] (select t1[1])
    // X3 = [  x8 | x13 |  x6 |  x7 ] (select t2[1])

    X1 = _mm_blend_epi16(X1, T3, 0x0c);
    X2 = _mm_blend_epi16(X2, T1, 0x0c);
    X3 = _mm_blend_epi16(X3, T2, 0x0c);

    // X0 = [  x0 |  x5 | x10 | x15 ] (nop)
    // X1 = [  x4 |  x9 | x14 |  x3 ] (select t2[2])
    // X2 = [ x12 |  x1 |  x6 | x11 ] (select t3[2])
    // X3 = [  x8 | x13 |  x2 |  x7 ] (select t1[2])

    X1 = _mm_blend_epi16(X1, T2, 0x30);
    X2 = _mm_blend_epi16(X2, T3, 0x30);
    X3 = _mm_blend_epi16(X3, T1, 0x30);

    for (i = ROUNDS;i > 0;i -= 2) {
        // X0 = [  x0 |  x5 | x10 | x15 ] (nop)
        // X1 = [  x4 |  x9 | x14 |  x3 ] (nop)
        // X2 = [ x12 |  x1 |  x6 | x11 ] (nop)
        // X3 = [  x8 | x13 |  x2 |  x7 ] (nop)

        // t0 = X0 + X2
        // t4 = sll(t0, 7)
        // t0 = srl(t0, 32 - 7)
        // t4 = or(t0, t4)
        // X1 ^= t4

        T0 = _mm_add_epi32(X0, X2);
        T4 = _mm_slli_epi32(T0, 7);
        T0 = _mm_srli_epi32(T0, 32 - 7);
        T4 = _mm_or_si128(T0, T4);
        X1 = _mm_xor_si128(X1, T4);

        // t1 = X1 + X0
        // t5 = sll(t1, 9)
        // t1 = srl(t1, 32 - 9)
        // t5 = or(t1, t5)
        // X3 ^= t5

        T1 = _mm_add_epi32(X1, X0);
        T5 = _mm_slli_epi32(T1, 9);
        T1 = _mm_srli_epi32(T1, 32 - 9);
        T5 = _mm_or_si128(T1, T5);
        X3 = _mm_xor_si128(X3, T5);

        // t2 = X3 + X1
        // t6 = sll(t2, 13)
        // t2 = srl(t2, 32 - 13)
        // t6 = or(t2, t6)
        // X2 ^= t6

        T2 = _mm_add_epi32(X3, X1);
        T6 = _mm_slli_epi32(T2, 13);
        T2 = _mm_srli_epi32(T2, 32 - 13);
        T6 = _mm_or_si128(T2, T6);
        X2 = _mm_xor_si128(X2, T6);

        // t3 = X2 + X3
        // t7 = sll(t3, 18)
        // t3 = srl(t3, 32 - 18)
        // t7 = or(t3, t7)
        // X0 ^= t7

        T3 = _mm_add_epi32(X2, X3);
        T7 = _mm_slli_epi32(T3, 18);
        T3 = _mm_srli_epi32(T3, 32 - 18);
        T7 = _mm_or_si128(T3, T7);
        X0 = _mm_xor_si128(X0, T7);

        // X0 = [  x0 |  x5 | x10 | x15 ] (nop)
        // X1 = [  x3 |  x4 |  x9 | x14 ] (shuffle X1)
        // X2 = [  x1 |  x6 | x11 | x12 ] (shuffle X2)
        // X3 = [  x2 |  x7 |  x8 | x13 ] (shuffle X3)

        T1 = _mm_set_epi32(0x0b0a0908, 0x07060504, 0x03020100, 0x0f0e0d0c);
        T2 = _mm_set_epi32(0x03020100, 0x0f0e0d0c, 0x0b0a0908, 0x07060504);
        T3 = _mm_set_epi32(0x07060504, 0x03020100, 0x0f0e0d0c, 0x0b0a0908);

        X1 = _mm_shuffle_epi8(X1, T1);
        X2 = _mm_shuffle_epi8(X2, T2);
        X3 = _mm_shuffle_epi8(X3, T3);

        // t0 = X0 + X1
        // t4 = sll(t0, 7)
        // t0 = srl(t0, 32 - 7)
        // t4 = or(t0, 4)
        // X2 ^= t4

        T0 = _mm_add_epi32(X0, X1);
        T4 = _mm_slli_epi32(T0, 7);
        T0 = _mm_srli_epi32(T0, 32 - 7);
        T4 = _mm_or_si128(T0, T4);
        X2 = _mm_xor_si128(X2, T4);

        // t1 = X2 + X0
        // t5 = sll(t1, 9)
        // t1 = srl(t1, 32 - 9)
        // t5 = or(t1, t5)
        // X3 ^= t5

        T1 = _mm_add_epi32(X2, X0);
        T5 = _mm_slli_epi32(T1, 9);
        T1 = _mm_srli_epi32(T1, 32 - 9);
        T5 = _mm_or_si128(T1, T5);
        X3 = _mm_xor_si128(X3, T5);

        // t2 = X3 + X2
        // t6 = sll(t2, 13)
        // t2 = srl(t2, 32 - 13)
        // t6 = or(t2, t6)
        // X1 ^= t6

        T2 = _mm_add_epi32(X3, X2);
        T6 = _mm_slli_epi32(T2, 13);
        T2 = _mm_srli_epi32(T2, 32 - 13);
        T6 = _mm_or_si128(T2, T6);
        X1 = _mm_xor_si128(X1, T6);

        // t3 = X1 + X3
        // t7 = sll(t3, 18)
        // t3 = srl(t3, 32 - 18)
        // t7 = or(t3, t7)
        // X0 ^= t7

        T3 = _mm_add_epi32(X1, X3);
        T7 = _mm_slli_epi32(T3, 18);
        T3 = _mm_srli_epi32(T3, 32 - 18);
        T7 = _mm_or_si128(T3, T7);
        X0 = _mm_xor_si128(X0, T7);

        // X0 = [  x0 |  x5 | x10 | x15 ] (nop)
        // X1 = [  x4 |  x9 | x14 |  x3 ] (shuffle X1)
        // X2 = [ x12 |  x1 |  x6 | x11 ] (shuffle X2)
        // X3 = [  x8 | x13 |  x2 |  x7 ] (shuffle X3)

        T1 = _mm_set_epi32(0x03020100, 0x0f0e0d0c, 0x0b0a0908, 0x07060504);
        T2 = _mm_set_epi32(0x0b0a0908, 0x07060504, 0x03020100, 0x0f0e0d0c);
        T3 = _mm_set_epi32(0x07060504, 0x03020100, 0x0f0e0d0c, 0x0b0a0908);

        X1 = _mm_shuffle_epi8(X1, T1);
        X2 = _mm_shuffle_epi8(X2, T2);
        X3 = _mm_shuffle_epi8(X3, T3);
    }

    // Y0 = [  x0 |  x5 | x10 | x15 ] (copy X0)
    // Y1 = [  x4 |  x9 | x14 |  x3 ] (copy X1)
    // Y2 = [  x8 | x13 |  x2 |  x7 ] (copy X3)
    // Y3 = [ x12 |  x1 |  x6 | x11 ] (copy X2)

    Y0 = X0;
    Y1 = X1;
    Y2 = X3;
    Y3 = X2;

    // Y0 = [  x0 |  x1 | x10 | x15 ] (select X2[1])
    // Y1 = [  x4 |  x5 | x14 |  x3 ] (select X0[1])
    // Y2 = [  x8 |  x9 |  x2 |  x7 ] (select X1[1])
    // Y3 = [ x12 | x13 |  x6 | x11 ] (select X3[1])

    Y0 = _mm_blend_epi16(Y0, X2, 0x0c);
    Y1 = _mm_blend_epi16(Y1, X0, 0x0c);
    Y2 = _mm_blend_epi16(Y2, X1, 0x0c);
    Y3 = _mm_blend_epi16(Y3, X3, 0x0c);

    // Y0 = [  x0 |  x1 |  x2 | x15 ] (select X3[2])
    // Y1 = [  x4 |  x5 |  x6 |  x3 ] (select X2[2])
    // Y2 = [  x8 |  x9 | x10 |  x7 ] (select X0[2])
    // Y3 = [ x12 | x13 | x14 | x11 ] (select X1[2])

    Y0 = _mm_blend_epi16(Y0, X3, 0x30);
    Y1 = _mm_blend_epi16(Y1, X2, 0x30);
    Y2 = _mm_blend_epi16(Y2, X0, 0x30);
    Y3 = _mm_blend_epi16(Y3, X1, 0x30);

    // Y0 = [  x0 |  x1 |  x2 |  x3 ] (select X1[3])
    // Y1 = [  x4 |  x5 |  x6 |  x7 ] (select X3[3])
    // Y2 = [  x8 |  x9 | x10 | x11 ] (select X2[3])
    // Y3 = [ x12 | x13 | x14 | x15 ] (select X0[3])

    Y0 = _mm_blend_epi16(Y0, X1, 0xc0);
    Y1 = _mm_blend_epi16(Y1, X3, 0xc0);
    Y2 = _mm_blend_epi16(Y2, X2, 0xc0);
    Y3 = _mm_blend_epi16(Y3, X0, 0xc0);

    // t0 = [  j0 |  j5 | j10 | j15 ] (load c || load constants)
    // t1 = [  j1 |  j2 |  j3 |  j4 ] (load k)
    // t2 = [ j11 | j12 | j13 | j14 ] (load k + 16)
    // t3 = [  j6 |  j7 |  j8 |  j9 ] (load in)

    if (c == NULL) {
        T0 = _mm_set_epi32(0x6b206574, 0x79622d32, 0x3320646e, 0x61707865);
    } else {
        T0 = _mm_load_si128((const __m128i *)(c));
    }

    T1 = _mm_load_si128((const __m128i *)(k));
    T2 = _mm_load_si128((const __m128i *)(k) + 1);
    T3 = _mm_load_si128((const __m128i *)(in));

    // t0 = [  j0 |  j5 | j10 | j15 ] (nop)
    // t1 = [  j4 |  j1 |  j2 |  j3 ] (shuffle t1)
    // t2 = [ j12 | j13 | j14 | j11 ] (shuffle t2)
    // t3 = [  j8 |  j9 |  j6 |  j7 ] (shuffle t3)

    T5 = _mm_set_epi32(0x0b0a0908, 0x07060504, 0x03020100, 0x0f0e0d0c);
    T6 = _mm_set_epi32(0x03020100, 0x0f0e0d0c, 0x0b0a0908, 0x07060504);
    T7 = _mm_set_epi32(0x07060504, 0x03020100, 0x0f0e0d0c, 0x0b0a0908);

    T1 = _mm_shuffle_epi8(T1, T5);
    T2 = _mm_shuffle_epi8(T2, T6);
    T3 = _mm_shuffle_epi8(T3, T7);

    // t4 = [  j0 |  j1 |  j2 |  j3 ] (select(t0, t1, t1 ,t1)
    // t5 = [  j4 |  j5 |  j2 |  j3 ] (select(t1, t0, t1, t1)
    // t6 = [ j12 | j13 | j14 | j15 ] (select(t2, t2, t2, t0)
    // t7 = [  j8 |  j9 | j10 |  j7 ] (select(t3, t3, t0, t3)

    T4 = _mm_blend_epi16(T0, T1, 0xfc);
    T5 = _mm_blend_epi16(T0, T1, 0xf3);
    T6 = _mm_blend_epi16(T0, T2, 0x3f);
    T7 = _mm_blend_epi16(T0, T3, 0xcf);

    // t4 = [  j0 |  j1 |  j2 |  j3 ] (nop)
    // t5 = [  j4 |  j5 |  j6 |  j7 ] (select(t5, t5, t3, t3)
    // t6 = [ j12 | j13 | j14 | j15 ] (nop)
    // t7 = [  j8 |  j9 | j10 | j11 ] (select(t7, t7, t7, t2)

    T5 = _mm_blend_epi16(T5, T3, 0xf0);
    T7 = _mm_blend_epi16(T7, T2, 0xc0);

    // Y0 += t4
    // Y1 += t5
    // Y2 += t7
    // Y3 += t6

    Y0 = _mm_add_epi32(Y0, T4);
    Y1 = _mm_add_epi32(Y1, T5);
    Y2 = _mm_add_epi32(Y2, T7);
    Y3 = _mm_add_epi32(Y3, T6);

    // store(out     , Y0)
    // store(out + 16, Y1)
    // store(out + 32, Y2)
    // store(out + 48, Y3)

    _mm_store_si128((__m128i *)(out) + 0, Y0);
    _mm_store_si128((__m128i *)(out) + 1, Y1);
    _mm_store_si128((__m128i *)(out) + 2, Y2);
    _mm_store_si128((__m128i *)(out) + 3, Y3);

    return 0;
}
