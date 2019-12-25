#pragma once

#include <vector>
#include <stdexcept>
#include <map>
// #include <leveldb/db.h>
#include "block.hpp"

constexpr char BLOCKCHAIN_TIP_KEY[] = "tip";

using BlockchainDb = std::map<std::string, std::string>;

class Blockchain
{
public:
    Blockchain(const json& j);
    Blockchain(const std::string& jsonStr):
        Blockchain(json::parse(jsonStr)) {}
    Blockchain() = default;

    void ResetWithGenesis()
    {
        m_db.clear();
        AddBlock(Block{"Genesis block", false, false, ""});
    }
    void AddBlock(const Block& block);
    bool Validate()     const;
    int  GetNumBlocks() const { return m_db.size() - 1; }; // -1 due to the tip key

    std::string Dump() const
    {
        return json(m_db).dump();
    }
    void Print() const
    {
        std::cout << std::setw(4) << json(m_db) << std::endl;
    }
    std::string GetTipHash() const { return m_tipHash; }

    Block FindLastIdentityBlock(const std::string& identityHash);

    const BlockchainDb& GetDb() const { return m_db; }
private:
    BlockchainDb m_db;
    std::string m_tipHash;
};

inline Blockchain::Blockchain(const json& j):
    m_db{j.get<BlockchainDb>()}
{
    if (m_db.empty())
    {
        ResetWithGenesis();
    }

    if (m_db.count(BLOCKCHAIN_TIP_KEY) != 0)
    {
        m_tipHash = m_db.at(BLOCKCHAIN_TIP_KEY);
    }
}

inline bool Blockchain::Validate() const
{
    if (m_db.count(BLOCKCHAIN_TIP_KEY) == 0)
    {
        return false;
    }

    auto hash = m_tipHash;
    for (auto i = GetNumBlocks(); i > 0; --i)
    {
        auto block = json::parse(m_db.at(hash)).get<Block>();
        if (!block.Validate())
        {
            return false;
        }
        
        hash = block.prevHash;
    }

    if (hash != "") return false; // we haven't reached the genesis block in GetNumBlocks iterations

    return true;
}

inline void Blockchain::AddBlock(const Block& block)
{
    if (block.prevHash != m_tipHash || !block.Validate())
    {
        return;
    }

    auto jsonBlock = json(block);
    std::cout << "New block:" << std::endl;
    std::cout << std::setw(4) << jsonBlock << std::endl;
    m_tipHash = block.hash;

    m_db[BLOCKCHAIN_TIP_KEY] = m_tipHash;
    m_db[block.hash] = jsonBlock.dump();
}

inline Block Blockchain::FindLastIdentityBlock(const std::string& identityHash)
{
    auto hash = m_tipHash;
    for (auto i = GetNumBlocks(); i > 0; --i)
    {
        auto block = json::parse(m_db.at(hash)).get<Block>();
        
        if (block.identityHash == identityHash)
        {
            return block;
        }
        hash = block.prevHash;
    }

    return Block();
}

inline void to_json(json& j, const Blockchain& blockchain) 
{
    j = json(blockchain.GetDb());
}