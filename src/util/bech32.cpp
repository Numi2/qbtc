#include <util/bech32.h>
#include <cctype>
#include <string>
#include <vector>

namespace {
// Generator coefficients for checksum
static const uint32_t GENERATOR[5] = {0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL, 0x2a1462b3UL};
// Bech32m constant
static const uint32_t BECH32M_CONST = 0x2bc830a3UL;

// Compute Bech32 polymod
uint32_t polymod(const std::vector<int>& v) {
    uint32_t chk = 1;
    for (int x : v) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ x;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) chk ^= GENERATOR[i];
        }
    }
    return chk;
}

// Expand HRP for checksum computation
std::vector<int> hrp_expand(const std::string& hrp) {
    std::vector<int> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) ret.push_back((c >> 5) & 0x07);
    ret.push_back(0);
    for (char c : hrp) ret.push_back(c & 0x1f);
    return ret;
}

// Create checksum
std::vector<int> create_checksum(const std::string& hrp, const std::vector<int>& data, bech32::Encoding enc) {
    std::vector<int> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);
    uint32_t mod = polymod(values) ^ (enc == bech32::Encoding::BECH32 ? 1 : BECH32M_CONST);
    std::vector<int> ret(6);
    for (int i = 0; i < 6; ++i) {
        ret[i] = (mod >> (5 * (5 - i))) & 0x1f;
    }
    return ret;
}

// Verify checksum and detect encoding
bool verify_checksum(const std::string& hrp, const std::vector<int>& values, bech32::Encoding& enc) {
    std::vector<int> exp = hrp_expand(hrp);
    exp.insert(exp.end(), values.begin(), values.end());
    uint32_t mod = polymod(exp);
    if (mod == 1) {
        enc = bech32::Encoding::BECH32;
        return true;
    }
    if (mod == BECH32M_CONST) {
        enc = bech32::Encoding::BECH32M;
        return true;
    }
    return false;
}
} // namespace

namespace bech32 {
bool Decode(const std::string& str, std::string& hrp, std::vector<int>& data, Encoding& encoding) {
    // Only support lower-case
    for (unsigned char c : str) {
        if (c < 33 || c > 126 || isupper(c)) return false;
    }
    size_t pos = str.rfind('1');
    if (pos == std::string::npos || pos == 0 || pos + 7 > str.size()) return false;
    hrp = str.substr(0, pos);
    std::vector<int> values;
    values.reserve(str.size() - pos - 1);
    for (size_t i = pos + 1; i < str.size(); ++i) {
        const char* p = strchr("qpzry9x8gf2tvdw0s3jn54khce6mua7l", str[i]);
        if (!p) return false;
        values.push_back(p - "qpzry9x8gf2tvdw0s3jn54khce6mua7l");
    }
    if (!verify_checksum(hrp, values, encoding)) return false;
    data.assign(values.begin(), values.end() - 6);
    return true;
}

std::string Encode(const std::string& hrp, const std::vector<int>& data, Encoding encoding) {
    std::string ret = hrp + '1';
    for (int d : data) {
        ret += "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[d];
    }
    std::vector<int> checksum = create_checksum(hrp, data, encoding);
    for (int d : checksum) {
        ret += "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[d];
    }
    return ret;
}
} // namespace bech32

bool ConvertBits(const std::vector<unsigned char>& in, int frombits, int tobits, bool pad, std::vector<int>& out) {
    uint32_t acc = 0;
    int bits = 0;
    const uint32_t maxv = (1 << tobits) - 1;
    out.clear();
    for (unsigned char v : in) {
        if (v >> frombits) return false;
        acc = (acc << frombits) | v;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) {
            out.push_back((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}