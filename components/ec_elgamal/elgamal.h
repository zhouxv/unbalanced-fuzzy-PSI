#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RCurve.h>

#include <cryptoTools/Network/Channel.h>
#include <vector>

using namespace osuCrypto;

inline std::vector<u8> block_to_u8vec(osuCrypto::block a,
                                      int size_curve_points) {

  u8 var8[16];
  memcpy(var8, &a, sizeof(var8));
  std::vector<u8> dest(16);
  for (u64 i = 0; i < 16; i++) {
    dest[i] = var8[sizeof(var8) - i - 1];
  }
  // pad zero for the 16 high bit.
  std::vector<u8> zero_high(size_curve_points - 16, 0);
  dest.insert(dest.begin(), zero_high.begin(), zero_high.end());

  return dest;
}

inline osuCrypto::block u8vec_to_block(std::vector<u8> dest,
                                       int size_curve_points) {
  u8 var8[16];

  for (u64 i = 0; i < 16; i++) {
    var8[sizeof(var8) - i - 1] = dest[size_curve_points - 16 + i];
  }

  osuCrypto::block a;

  memcpy(&a, &var8, sizeof(a));

  return a;
}

// u8 vec -> 2 block
inline std::vector<osuCrypto::block> u8vec_to_blocks(std::vector<u8> dest) {
  u8 var8_1[16];
  u8 var8_2[16];
  std::vector<osuCrypto::block> result;
  osuCrypto::block a;

  for (u64 i = 0; i < 16; i++) {
    var8_1[sizeof(var8_1) - i - 1] = dest[16 + i];
    var8_2[sizeof(var8_2) - i - 1] = dest[i];
  }

  memcpy(&a, &var8_2, sizeof(a));
  result.push_back(a);
  memcpy(&a, &var8_1, sizeof(a));
  result.push_back(a);

  return result;
}

// 2 block -> vec u8
inline std::vector<u8> blocks_to_u8vec(std::vector<osuCrypto::block> a) {
  u8 var8_1[16];
  memcpy(var8_1, &a[0], sizeof(var8_1));
  u8 var8_2[16];
  memcpy(var8_2, &a[1], sizeof(var8_2));

  std::vector<u8> dest(32);
  for (u64 i = 0; i < 16; i++) {
    dest[i] = var8_1[sizeof(var8_1) - i - 1];
    dest[i + 16] = var8_2[sizeof(var8_2) - i - 1];
  }

  return dest;
}

inline std::vector<osuCrypto::block> num_vec_to_blocks(std::vector<u8> vec) {

  std::vector<osuCrypto::block> a;

  u8 var8_1[16];
  u8 var8_2[16];
  osuCrypto::block b1; // ctx[1:16]
  osuCrypto::block b2; // ctx[17:33]

  for (u64 i = 0; i < 16; i++) {
    var8_1[i] = vec[vec.size() - 16 - 1 - i];
    var8_2[i] = vec[vec.size() - 1 - i];
  }

  memcpy(&b1, &var8_1, sizeof(a));
  memcpy(&b2, &var8_2, sizeof(a));

  a.push_back(b1);
  a.push_back(b2);

  return a;
}

inline std::vector<osuCrypto::block> point_vec_to_blocks(std::vector<u8> vec) {

  std::vector<osuCrypto::block> a;

  if (vec[0] == 0) {
    a.push_back(toBlock(u64(0)));
  } else {
    a.push_back(toBlock(u64(1)));
  }

  // vec.erase(vec.begin());

  std::vector<osuCrypto::block> b = num_vec_to_blocks(vec);

  a.insert(a.end(), b.begin(), b.end());

  return a;
}

inline std::vector<u8> blocks_to_num_vec(std::vector<osuCrypto::block> blocks) {

  std::vector<u8> vec(32);
  u8 var8_1[16];
  u8 var8_2[16];

  memcpy(&var8_1, &blocks[0], sizeof(var8_1));
  memcpy(&var8_2, &blocks[1], sizeof(var8_2));

  for (u64 i = 0; i < 16; i++) {
    vec[i] = var8_1[16 - 1 - i];
    vec[i + 16] = var8_2[16 - 1 - i];
  }

  return vec;
}

inline std::vector<u8>
blocks_to_point_vec(std::vector<osuCrypto::block> blocks) {
  u8 first_bit;
  if (blocks[0] == toBlock(u64(0))) {
    first_bit = 0;
  } else {
    first_bit = 1;
  }

  blocks.erase(blocks.begin());

  std::vector<u8> vec = blocks_to_num_vec(blocks);

  vec.insert(vec.begin(), first_bit);

  return vec;
}

// 存编码信息，其余存点数据）
inline std::vector<osuCrypto::block>
ciphertexts_to_blocks(std::vector<std::vector<u8>> &ctx) {
  std::vector<u8> ctx1 = ctx[0];
  std::vector<u8> ctx2 = ctx[1];

  std::vector<osuCrypto::block> a;

  osuCrypto::block b;
  if (ctx1[0] == 2 && ctx2[0] == 2)
    b = toBlock(u64(0));
  else if (ctx1[0] == 2 && ctx2[0] == 3)
    b = toBlock(u64(1));
  else if (ctx1[0] == 3 && ctx2[0] == 2)
    b = toBlock(u64(2));
  else if (ctx1[0] == 3 && ctx2[0] == 3)
    b = toBlock(u64(3));

  a.push_back(b);

  u8 var8_1[16];
  u8 var8_2[16];
  osuCrypto::block ctx_1; // ctx[1:16]
  osuCrypto::block ctx_2; // ctx[17:33]

  for (u64 i = 0; i < 16; i++) {
    var8_1[i] = ctx1[ctx1.size() - 16 - 1 - i];
    var8_2[i] = ctx1[ctx1.size() - 1 - i];
  }

  memcpy(&ctx_1, &var8_1, sizeof(ctx_1));
  memcpy(&ctx_2, &var8_2, sizeof(ctx_2));

  a.push_back(ctx_1);
  a.push_back(ctx_2);

  for (u64 i = 0; i < 16; i++) {
    var8_1[i] = ctx2[ctx2.size() - 16 - 1 - i];
    var8_2[i] = ctx2[ctx2.size() - 1 - i];
  }

  memcpy(&ctx_1, &var8_1, sizeof(ctx_1));
  memcpy(&ctx_2, &var8_2, sizeof(ctx_2));

  a.push_back(ctx_1);
  a.push_back(ctx_2);

  return a;
}

inline std::vector<std::vector<u8>>
rerandomize(std::vector<std::vector<u8>> ctx, std::vector<u8> pk_vec) {

  REllipticCurve curve; //(CURVE_25519)
  PRNG prng(_mm_set_epi32(19249, 4923, 233121465, 123));
  const auto &g = curve.getGenerator();
  REccNumber r(curve);
  r.randomize(prng);

  REccPoint gr(curve);
  gr = g * r;

  REccPoint pk(curve);
  pk.fromBytes(pk_vec.data());

  REccPoint ctx1(curve);
  REccPoint ctx2(curve);
  ctx1.fromBytes(ctx[0].data());
  ctx2.fromBytes(ctx[1].data());

  ctx1 += gr;
  ctx2 += pk * r;

  ctx1.toBytes(ctx[0].data());
  ctx2.toBytes(ctx[1].data());

  return ctx;
}

inline std::vector<std::vector<u8>>
rerandomize_o(std::vector<std::vector<u8>> ctx, REccPoint gr, REccPoint pkr) {

  REllipticCurve curve; //(CURVE_25519)
  // PRNG prng(_mm_set_epi32(19249, 4923, 233121465, 123));
  // const auto &g = curve.getGenerator();
  // REccNumber r(curve);
  // r.randomize(prng);

  // REccPoint gr(curve);
  // gr = g * r;

  // REccPoint pk(curve);
  // pk.fromBytes(pk_vec.data());

  REccPoint ctx1(curve);
  REccPoint ctx2(curve);
  ctx1.fromBytes(ctx[0].data());
  ctx2.fromBytes(ctx[1].data());

  ctx1 += gr;
  ctx2 += pkr;

  ctx1.toBytes(ctx[0].data());
  ctx2.toBytes(ctx[1].data());

  return ctx;
}

inline std::vector<std::vector<u8>>
blocks_to_ciphertexts(std::vector<osuCrypto::block> blocks) {

  std::vector<std::vector<u8>> a;
  std::vector<u8> ctx1(32);
  std::vector<u8> ctx2(32);

  u8 var8_1[16];
  u8 var8_2[16];
  osuCrypto::block ctx_1;
  osuCrypto::block ctx_2;

  memcpy(&var8_1, &blocks[1], sizeof(var8_1));
  memcpy(&var8_2, &blocks[2], sizeof(var8_2));

  for (u64 i = 0; i < 16; i++) {
    ctx1[i] = var8_1[16 - 1 - i];
    ctx1[i + 16] = var8_2[16 - 1 - i];
  }

  memcpy(&var8_1, &blocks[3], sizeof(var8_1));
  memcpy(&var8_2, &blocks[4], sizeof(var8_2));

  for (u64 i = 0; i < 16; i++) {
    ctx2[i] = var8_1[16 - 1 - i];
    ctx2[i + 16] = var8_2[16 - 1 - i];
  }

  // std::cout << "before insert" << std::endl;

  if (blocks[0] == toBlock(u64(0))) {
    ctx1.insert(ctx1.begin(), 2);
    ctx2.insert(ctx2.begin(), 2);
  } else if (blocks[0] == toBlock(u64(1))) {
    ctx1.insert(ctx1.begin(), 2);
    ctx2.insert(ctx2.begin(), 3);
  } else if (blocks[0] == toBlock(u64(2))) {
    ctx1.insert(ctx1.begin(), 3);
    ctx2.insert(ctx2.begin(), 2);
  } else if (blocks[0] == toBlock(u64(3))) {
    ctx1.insert(ctx1.begin(), 3);
    ctx2.insert(ctx2.begin(), 3);
  }
  // std::cout << "after insert" << std::endl;

  a.push_back(ctx1);
  a.push_back(ctx2);

  return a;
}

inline std::vector<std::vector<u8>>
encryption(std::vector<u8> m_vec, std::vector<u8> pk_vec, PRNG &prng_enc) {
  // Encryption and Decryption testing (ElGamal)
  REllipticCurve curve; //(CURVE_25519)

  // generater g
  const auto &g = curve.getGenerator();

  REccPoint pk;
  pk.fromBytes(pk_vec.data());

  m_vec.insert(m_vec.begin(), 2);

  REccPoint m(curve);

  m.fromBytes(m_vec.data());

  REccNumber r(curve);
  r.randomize(prng_enc);

  REccPoint c1 = g * r;
  REccPoint c2 = m + pk * r;

  std::vector<u8> c1_vec(g.sizeBytes());
  std::vector<u8> c2_vec(g.sizeBytes());

  c1.toBytes(c1_vec.data());
  c2.toBytes(c2_vec.data());

  std::vector<std::vector<u8>> ciphertext;
  ciphertext.push_back(c1_vec);
  ciphertext.push_back(c2_vec);

  return ciphertext;
}

inline std::vector<std::vector<u8>>
encryption_r(std::vector<u8> m_vec, std::vector<u8> pk_vec, PRNG &prng_enc) {
  // Encryption and Decryption testing (ElGamal)
  REllipticCurve curve; //(CURVE_25519)

  // generater g
  const auto &g = curve.getGenerator();
  // std::cout <<g.sizeBytes()<< std::endl;
  // sk

  REccPoint pk;
  pk.fromBytes(pk_vec.data());

  m_vec.insert(m_vec.begin(), 2);

  REccPoint m(curve);

  m.fromBytes(m_vec.data());
  // std::cout<<" 6 " <<std::endl;
  REccNumber r(curve);
  r.randomize(prng_enc);

  REccPoint c1; //= g * r;
  REccPoint c2 = m + pk * r;

  std::vector<u8> c1_vec(g.sizeBytes());
  std::vector<u8> c2_vec(g.sizeBytes());

  c1.toBytes(c1_vec.data());
  c2.toBytes(c2_vec.data());

  std::vector<std::vector<u8>> ciphertext;
  ciphertext.push_back(c1_vec);
  ciphertext.push_back(c2_vec);

  return ciphertext;
}

inline std::vector<u8> decryption(std::vector<std::vector<u8>> ciphertext,
                                  std::vector<u8> sk_vec) {
  REllipticCurve curve; //(CURVE_25519)

  REccPoint c1;
  REccPoint c2;
  REccNumber sk;
  c1.fromBytes(ciphertext[0].data());
  c2.fromBytes(ciphertext[1].data());
  sk.fromBytes(sk_vec.data());
  // comment out for comparision
  REccPoint dec_m = c2 - c1 * sk;

  std::vector<u8> dec_m_vec(33);
  // std::cout<<"size: "<<dec_m_vec.size()<<std::endl;
  dec_m.toBytes(dec_m_vec.data());

  dec_m_vec.erase(dec_m_vec.begin());

  // print_u8vec(dec_m_vec);

  // block dec_message = u8vec_to_block(dec_m_vec,32);
  // std::cout << "decode message: "<<dec_message << std::endl;
  return dec_m_vec;
}

inline std::vector<std::vector<u8>>
partial_decryption(std::vector<std::vector<u8>> ciphertext,
                   std::vector<u8> sk_vec) {
  // output a ctx
  REllipticCurve curve; //(CURVE_25519)

  REccPoint c1;
  REccPoint c2;
  REccNumber sk;
  c1.fromBytes(ciphertext[0].data());
  c2.fromBytes(ciphertext[1].data());
  sk.fromBytes(sk_vec.data());

  // REccPoint r;
  // r.randomize(prng_dec);

  // comment out for comparision
  c2 -= c1 * sk;
  std::vector<u8> new_ctx1 = ciphertext[0];
  std::vector<u8> new_ctx2(33);
  c2.toBytes(new_ctx2.data());

  std::vector<std::vector<u8>> ctx;
  ctx.push_back(new_ctx1);
  ctx.push_back(new_ctx2);

  return ctx;
}
