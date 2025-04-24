// Key I/O implementation for QuBitcoin: Bech32m PQC address logic
#include <key_io.h>
#include <util/strencodings.h>
#include <util/bech32.h>

static const std::string QBC_HRP = "qbc";

std::string EncodeDestination(const CTxDestination& dest) {
    if (auto w = std::get_if<WitnessUnknown>(&dest)) {
        int version = w->GetWitnessVersion();
        const auto& prog = w->GetWitnessProgram();
        if (version == 1 && prog.size() >= 2 && prog.size() <= 40) {
            std::vector<int> data;
            data.push_back(version);
            std::vector<int> prog5;
            if (!ConvertBits(prog, 8, 5, true, prog5)) return std::string();
            data.insert(data.end(), prog5.begin(), prog5.end());
            return bech32::Encode(QBC_HRP, data, bech32::Encoding::BECH32M);
        }
    }
    return std::string();
}

CTxDestination DecodeDestination(const std::string& address, std::string& error_msg, std::vector<int>* error_locations) {
    std::string hrp;
    std::vector<int> data;
    bech32::Encoding enc;
    if (!bech32::Decode(address, hrp, data, enc)) {
        error_msg = "Invalid Bech32m encoding";
        return CNoDestination();
    }
    if (hrp != QBC_HRP) {
        error_msg = "Invalid address prefix: " + hrp;
        return CNoDestination();
    }
    if (data.empty()) {
        error_msg = "Empty data in address";
        return CNoDestination();
    }
    int version = data[0];
    if (version != 1) {
        error_msg = "Unsupported witness version: " + std::to_string(version);
        return CNoDestination();
    }
    std::vector<int> prog5(data.begin() + 1, data.end());
    std::vector<unsigned char> prog;
    if (!ConvertBits(prog5, 5, 8, false, prog)) {
        error_msg = "Invalid program bits";
        return CNoDestination();
    }
    if (prog.size() < 2 || prog.size() > 40) {
        error_msg = "Invalid program length: " + std::to_string(prog.size());
        return CNoDestination();
    }
    if (enc != bech32::Encoding::BECH32M) {
        error_msg = "Invalid encoding for version";
        return CNoDestination();
    }
    return WitnessUnknown{version, prog};
}