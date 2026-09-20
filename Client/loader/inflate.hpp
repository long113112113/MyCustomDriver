#pragma once
//
// Minimal self-contained raw DEFLATE (RFC 1951) decompressor.
// Decodes stored, fixed-Huffman and dynamic-Huffman blocks. No OS/CRT
// dependencies beyond memcpy-size logic, so behaviour is identical on the
// build machine and on the target. Verified against System.IO.Compression.
//
#include <cstdint>
#include <cstring>
#include <vector>

namespace inflate {

namespace detail {

const int kMaxBits = 15;

struct Huffman {
  short count[kMaxBits + 1]; // code length -> count
  short symbol[288 + 32];    // canonical symbol table
};

// Build a canonical Huffman decode table from code lengths.
// Returns 0 on success, negative on over-subscription/oversubscribed input.
inline int Construct(Huffman& h, const short* length, int n) {
  int left, off[kMaxBits + 1];
  for (int len = 0; len <= kMaxBits; len++)
    h.count[len] = 0;
  for (int s = 0; s < n; s++)
    h.count[length[s]]++;
  if (h.count[0] == n) // complete set with no codes (empty block)
    return 0;
  left = 1;
  for (int len = 1; len <= kMaxBits; len++) {
    left <<= 1;
    left -= h.count[len];
    if (left < 0)
      return left; // over-subscribed
  }
  off[1] = 0;
  for (int len = 1; len < kMaxBits; len++)
    off[len + 1] = off[len] + h.count[len];
  for (int s = 0; s < n; s++)
    if (length[s] != 0)
      h.symbol[off[length[s]]++] = (short)s;
  return 0;
}

struct BitReader {
  const uint8_t* src;
  size_t srcLen;
  size_t pos;
  uint32_t bitbuf;
  int bitcnt;

  BitReader(const uint8_t* s, size_t n) : src(s), srcLen(n), pos(0), bitbuf(0), bitcnt(0) {}

  bool NeedBits(int n) {
    while (bitcnt < n) {
      if (pos >= srcLen)
        return false;
      bitbuf |= ((uint32_t)src[pos++] << bitcnt);
      bitcnt += 8;
    }
    return true;
  }

  bool Bits(int n, int& value) {
    if (!NeedBits(n))
      return false;
    value = (int)(bitbuf & ((1u << n) - 1));
    bitbuf >>= n;
    bitcnt -= n;
    return true;
  }

  // Decode one canonical code from table h.
  bool Decode(const Huffman& h, int& symbol) {
    int code = 0, first = 0, index = 0, len = 1;
    for (; len <= kMaxBits; len++) {
      if (!NeedBits(1))
        return false;
      code |= (bitbuf & 1);
      int count = h.count[len];
      if (code - count < first) { // symbol found
        bitbuf >>= 1;
        bitcnt--;
        symbol = h.symbol[index + (code - first)];
        return true;
      }
      bitbuf >>= 1;
      bitcnt--;
      index += count;
      first += count;
      first <<= 1;
      code <<= 1;
    }
    return false; // invalid code
  }
};

} // namespace detail

// Inflate a raw deflate stream `in` into `out`. `expected` is the exact
// required output size; the caller verifies it so a corrupt payload is
// rejected instead of producing a bogus image. Returns true on success.
inline bool Inflate(const std::vector<uint8_t>& in, std::vector<uint8_t>& out,
                    size_t expected) {
  using namespace detail;
  if (in.empty())
    return false;
  BitReader br(in.data(), in.size());
  out.clear();
  out.reserve(expected);

  int last = 0;
  do {
    if (!br.Bits(1, last))
      return false;
    int type = 0;
    if (!br.Bits(2, type))
      return false;

    if (type == 0) { // stored
      // Discard bits to byte boundary.
      while (br.bitcnt >= 8) {
        br.bitbuf >>= 8;
        br.bitcnt -= 8;
      }
      int len = 0, nlen = 0;
      if (!br.Bits(16, len) || !br.Bits(16, nlen))
        return false;
      if (len != (~nlen & 0xFFFF))
        return false;
      if (out.size() + (size_t)len > expected)
        return false;
      if (br.pos + (size_t)len > br.srcLen)
        return false;
      out.insert(out.end(), br.src + br.pos, br.src + br.pos + len);
      br.pos += (size_t)len;
      continue;
    }

    Huffman lit, dist;
    if (type == 1) { // fixed
      short lcode[288], dcode[30];
      for (int i = 0; i < 144; i++)
        lcode[i] = 8;
      for (int i = 144; i < 256; i++)
        lcode[i] = 9;
      for (int i = 256; i < 280; i++)
        lcode[i] = 7;
      for (int i = 280; i < 288; i++)
        lcode[i] = 8;
      for (int i = 0; i < 30; i++)
        dcode[i] = 5;
      if (Construct(lit, lcode, 288) != 0 || Construct(dist, dcode, 30) != 0)
        return false;
    } else if (type == 2) { // dynamic
      int hlit = 0, hdist = 0, hclen = 0;
      if (!br.Bits(5, hlit) || !br.Bits(5, hdist) || !br.Bits(4, hclen))
        return false;
      hlit += 257;
      hdist += 1;
      hclen += 4;
      short order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
      short clens[19] = {0};
      for (int i = 0; i < hclen; i++) {
        int v = 0;
        if (!br.Bits(3, v))
          return false;
        clens[order[i]] = (short)v;
      }
      Huffman cl;
      if (Construct(cl, clens, 19) != 0)
        return false;
      if (cl.count[0] == 19) // no code-length codes -> invalid
        return false;
      short lens[288 + 32];
      int n = hlit + hdist;
      int i = 0;
      while (i < n) {
        int sym = 0;
        if (!br.Decode(cl, sym))
          return false;
        if (sym < 16) {
          lens[i++] = (short)sym;
        } else if (sym == 16) {
          if (i == 0)
            return false;
          int rep = 0;
          if (!br.Bits(2, rep))
            return false;
          rep += 3;
          short prev = lens[i - 1];
          for (int r = 0; r < rep; r++) {
            if (i >= n)
              return false;
            lens[i++] = prev;
          }
        } else if (sym == 17) {
          int rep = 0;
          if (!br.Bits(3, rep))
            return false;
          rep += 3;
          for (int r = 0; r < rep; r++) {
            if (i >= n)
              return false;
            lens[i++] = 0;
          }
        } else { // 18
          int rep = 0;
          if (!br.Bits(7, rep))
            return false;
          rep += 11;
          for (int r = 0; r < rep; r++) {
            if (i >= n)
              return false;
            lens[i++] = 0;
          }
        }
      }
      if (Construct(lit, lens, hlit) != 0 || Construct(dist, lens + hlit, hdist) != 0)
        return false;
    } else {
      return false; // reserved block type
    }

    // Decode literal/length sequence.
    static const short kLenBase[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
        51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    static const short kLenExtra[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3,
        3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    static const short kDistBase[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
        513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    static const short kDistExtra[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7,
        8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

    for (;;) {
      int sym = 0;
      if (!br.Decode(lit, sym))
        return false;
      if (sym < 256) {
        if (out.size() + 1 > expected)
          return false;
        out.push_back((uint8_t)sym);
      } else if (sym == 256) {
        break; // end of block
      } else {
        sym -= 257;
        if (sym < 0 || sym >= 29)
          return false;
        int len = kLenBase[sym];
        if (kLenExtra[sym] != 0) {
          int e = 0;
          if (!br.Bits(kLenExtra[sym], e))
            return false;
          len += e;
        }
        int dsym = 0;
        if (!br.Decode(dist, dsym))
          return false;
        if (dsym < 0 || dsym >= 30)
          return false;
        int dpos = kDistBase[dsym];
        if (kDistExtra[dsym] != 0) {
          int e = 0;
          if (!br.Bits(kDistExtra[dsym], e))
            return false;
          dpos += e;
        }
        if ((size_t)dpos > out.size())
          return false; // distance too far; corrupt data
        if (out.size() + (size_t)len > expected)
          return false;
        size_t from = out.size() - (size_t)dpos;
        for (int r = 0; r < len; r++)
          out.push_back(out[from + (size_t)r]); // may copy from just-written bytes
      }
    }
  } while (!last);

  return out.size() == expected;
}

} // namespace inflate