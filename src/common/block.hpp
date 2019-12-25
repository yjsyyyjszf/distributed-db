#pragma once

#include <string>
#include <json.hpp>
#include "../common/crypto.hpp"

using json = nlohmann::json;

constexpr unsigned POW_TARGET_BITS{20};
static_assert(POW_TARGET_BITS % 4 == 0);

inline std::string GetPowTarget()
{
    std::string result(256 / 4, '0');
    result[POW_TARGET_BITS / 4 - 1] = '1';

    return result;
}

class Block
{
public:
    std::string identityHash;
    bool        readRights;
    bool        writeRights;
    std::string prevHash;
    unsigned    nonce;
    std::string hash;

    Block(const std::string& identityHash, bool read, bool write, const std::string& prevHash):
        identityHash{identityHash},
        readRights{read},
        writeRights{write},
        prevHash{prevHash},
        nonce{0}
    {
        Mine();
    }
    Block(): readRights{false}, writeRights{false}, nonce{0u} {}

    void Mine();
    bool Validate() const { return CalculateHash() <= GetPowTarget(); }

    std::string CalculateHash() const
    {
        return crypto::Sha256(identityHash +
                              std::to_string(readRights) +
                              std::to_string(writeRights) + 
                              prevHash +
                              std::to_string(nonce));
    }
};

inline void Block::Mine()
{
    do
    {
        nonce++;
        hash = CalculateHash();
    } while (hash > GetPowTarget());
}

inline void to_json(json& j, const Block& block) 
{
    j = json{
        {"identityHash", block.identityHash}, 
        {"readRights", block.readRights},
        {"writeRights", block.writeRights},
        {"prevHash", block.prevHash}, 
        {"nonce", block.nonce},
        {"hash", block.hash}
    };
}

inline void from_json(const json& j, Block& block)
{
    j.at("identityHash").get_to(block.identityHash);
    j.at("readRights").get_to(block.readRights);
    j.at("writeRights").get_to(block.writeRights);
    j.at("prevHash").get_to(block.prevHash);
    j.at("nonce").get_to(block.nonce);
    j.at("hash").get_to(block.hash);
}