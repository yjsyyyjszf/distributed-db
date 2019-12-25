#pragma once

#include <set>
#include <string>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <random>
#include <queue>
#include <json.hpp>
#include <sockpp/tcp_acceptor.h>
#include <leveldb/db.h>
#include "../common/blockchain.hpp"
#include "../common/network_api.hpp"
#include "../common/crypto.hpp"

using json = nlohmann::json;
using DataStorage = std::map<std::string, std::string>;

class Network
{
public:
    Network(in_port_t thisPort, bool initial, leveldb::DB* db):
        m_thisPort{thisPort},
        m_db{db},
        m_rand{std::random_device{}()},
        m_minerStop{false},
        m_miner{&Network::Miner, this}
    {
        if (initial)
        {
            m_blockchain.ResetWithGenesis();
        }

        AddPort(m_thisPort);
    }
    ~Network()
    {
        {
            std::unique_lock<std::mutex> lock(m_minerMutex);
            m_minerStop = true;
        }
        m_minerCond.notify_all();
        m_miner.join();
    }
    bool Join(in_port_t otherPort);
    void Listen();
    bool ValidateBlockchain() const
    {
        return m_blockchain.Validate();     
    }
private:
    in_port_t           m_thisPort;
    std::set<in_port_t> m_networkPorts;
    Blockchain          m_blockchain;
    std::mutex          m_portMutex;
    std::mutex          m_blockchainMutex;
    std::mutex          m_dataMutex;
    DataStorage         m_dataStorage;
    leveldb::DB*        m_db;
    std::mt19937        m_rand;

    std::queue<json>        m_minerTasks; 
    std::mutex              m_minerMutex;
    std::condition_variable m_minerCond;
    bool                    m_minerStop;
    std::thread             m_miner;

    // Request handlers
    void GetAllNodes(sockpp::tcp_socket sock);
    void AddNode(sockpp::tcp_socket sock);
    void PostBlockchain(sockpp::tcp_socket sock);
    void HandleAccess(sockpp::tcp_socket sock);
    void HandleData(sockpp::tcp_socket sock);

    json HandleHandshakeWithSalt(sockpp::tcp_socket& sock);

    void ConfigureServerResources();
    void AddPort(in_port_t port) 
    { 
        m_networkPorts.insert(port);
    }
    void UpdateBlockchain(const Blockchain& newBlockchain)
    {
        std::unique_lock<std::mutex> lock(m_blockchainMutex);
        if (!newBlockchain.Validate()) return;

        if (m_blockchain.GetNumBlocks() < newBlockchain.GetNumBlocks())
        {
            m_blockchain = newBlockchain;
            std::cout << "Updated blockchain: " << std::endl;
            m_blockchain.Print();
        }
    }
    void DoHandleAccess(const json& j);
    void Miner();
};

inline bool Network::Join(in_port_t otherPort)
{
    std::unique_lock<std::mutex> lock(m_portMutex);
    std::set<in_port_t> newPorts;
    if (!FillP2pPortSet(otherPort, newPorts))
    {
        return false;
    }

    for (auto port : newPorts)
    {
        if (m_networkPorts.count(port) == 1)
        {
            continue;
        }
        
        AddPort(port);

        sockpp::tcp_connector conn{{"192.168.43.128", port}};
        if (!conn)
        {
            std::cerr << "Error connecting to node at port " << port << "\n\t"
                      << conn.last_error_str() << std::endl;
            continue;
        }
        SendRequest(conn, NetworkRequest::AddNode);
        json msg;
        msg["port"] = m_thisPort;
        WriteJsonMessage(conn, msg);
        msg = ReadJsonMessage(conn);
        Blockchain rcv{msg};
        UpdateBlockchain(rcv);
    }

    return true;
}

inline void Network::Listen()
{
    sockpp::tcp_acceptor acc(m_thisPort);
    while (true)
    {
        sockpp::inet_address peer;
        
        sockpp::tcp_socket sock = acc.accept(&peer);
        if (!sock)
        {
            std::cerr << "Error accepting incoming connection from " << peer << ": " 
                        << acc.last_error_str() << std::endl;
        }

        uint16_t cmdBuf = 0;
        if (sock.read_n(&cmdBuf, sizeof(cmdBuf)) != sizeof(cmdBuf))
        {
            std::cerr << "Error reading request " << sock.last_error_str() << std::endl;
            return;
        }

        auto request = static_cast<NetworkRequest>(ntohs(cmdBuf));
        void (Network::*fun)(sockpp::tcp_socket sock) = nullptr;
        switch (request)
        {
        case NetworkRequest::GetAllNodes:
            fun = &Network::GetAllNodes;
            break;
        case NetworkRequest::AddNode:
            fun = &Network::AddNode;
            break;
        case NetworkRequest::PostBlockchain:
            fun = &Network::PostBlockchain;
            break;
        case NetworkRequest::HandleAccess:
            fun = &Network::HandleAccess;
            break;
        case NetworkRequest::HandleData:
            fun = &Network::HandleData;
            break;
        default:
            break;
        }

        std::thread thr(fun, this, std::move(sock));
        thr.detach();
    }
}

inline void Network::GetAllNodes(sockpp::tcp_socket sock)
{
    std::unique_lock<std::mutex> lock(m_portMutex);
    WriteJsonMessage(sock, json(m_networkPorts));
}
 
inline void Network::AddNode(sockpp::tcp_socket sock)
{
    std::unique_lock<std::mutex> lock(m_portMutex);

    json j = ReadJsonMessage(sock);
    in_port_t port = j["port"].get<in_port_t>();
    AddPort(port);

    {
        std::unique_lock<std::mutex> lock(m_blockchainMutex);
        WriteJsonMessage(sock, json(m_blockchain));
    }
    std::cout << "Node " << port << " has connected" << std::endl;
}

inline void Network::PostBlockchain(sockpp::tcp_socket sock)
{
    json j = ReadJsonMessage(sock);
    Blockchain rcv{j};
    UpdateBlockchain(rcv);
}

inline void Network::HandleAccess(sockpp::tcp_socket sock)
{
    json j = HandleHandshakeWithSalt(sock);
    if (!VerifyHandleAccessMessage(j))
    {
        return;
    }

    {
        std::unique_lock<std::mutex> lock(m_minerMutex);
        m_minerTasks.emplace(j);
    }
    m_minerCond.notify_one();
}

inline void Network::HandleData(sockpp::tcp_socket sock)
{
    auto j = HandleHandshakeWithSalt(sock);
    if (!VerifyHandleDataMessage(j))
    {
        json response;
        response["data"] = "Failed signature!";
        WriteJsonMessage(sock, response);
        return;
    }

    auto oper = j.at("oper").get<std::string>();
    std::string hash = GetIdentityHashFromMessage(j);
    std::unique_lock<std::mutex> lock(m_blockchainMutex);
    if (oper == "read")
    {
        if (j.at("from").get<std::string>() != "user" && !m_blockchain.FindLastIdentityBlock(hash).readRights)
        {
            json response;
            response["data"] = "Access denied!";
            WriteJsonMessage(sock, response);
            return;
        }

        std::unique_lock<std::mutex> lock{m_dataMutex};
        json response;
        std::string data;
        leveldb::Slice key(hash);
        auto status = m_db->Get(leveldb::ReadOptions(), key, &data);
        if (!status.ok()) std::cerr << status.ToString() << std::endl;
        //response["data"] = m_dataStorage[hash];
        response["data"] = data;
        WriteJsonMessage(sock, response);
    }
    else if (oper == "write")
    {
        if (j.at("from").get<std::string>() != "user" && !m_blockchain.FindLastIdentityBlock(hash).writeRights)
        {
            json response;
            response["data"] = "Access denied!";
            return;
        }

        std::unique_lock<std::mutex> lock{m_dataMutex};
        // m_dataStorage[hash] = j.at("data").get<std::string>();
        leveldb::Slice key(hash);
        auto status = m_db->Put(leveldb::WriteOptions(), key, j.at("data").get<std::string>());
        if (!status.ok()) std::cerr << status.ToString() << std::endl;
        std::cout << "Written data at " << hash << ": " << m_dataStorage[hash] << std::endl;
        json response;
        response["data"] = "ok";
        WriteJsonMessage(sock, response);
    }
    else
    {
        json response;
        response["data"] = "Wrong operation";
        WriteJsonMessage(sock, response);
        return;
    }
}

inline json Network::HandleHandshakeWithSalt(sockpp::tcp_socket& sock)
{
    json salt;
    salt["salt"] = crypto::Sha256(std::to_string(m_rand()));
    WriteJsonMessage(sock, salt);
    return ReadJsonMessage(sock);
}

inline void Network::DoHandleAccess(const json& j)
{
    std::string tipHash;
    {
        std::unique_lock<std::mutex> lock(m_blockchainMutex);
        tipHash = m_blockchain.GetTipHash();
    }

    Block newBlock{GetIdentityHashFromMessage(j),
                   j.at("readRights").get<bool>(),
                   j.at("writeRights").get<bool>(),
                   tipHash};
    {
        std::unique_lock<std::mutex> lock(m_blockchainMutex);
        m_blockchain.AddBlock(newBlock);
    }

    std::unique_lock<std::mutex> plock(m_portMutex);
    for (auto port : m_networkPorts)
    {
        if (port == m_thisPort) continue;

        std::string dump;
        {
            std::unique_lock<std::mutex> lock(m_blockchainMutex);
            sockpp::tcp_connector conn{{"192.168.43.128", port}};
            if (!conn) continue;
            SendRequest(conn, NetworkRequest::PostBlockchain);
            WriteJsonMessage(conn, json(m_blockchain));
        }
    }
}

inline void Network::Miner()
{
    for (;;)
    {
        json task;

        {
            std::unique_lock<std::mutex> lock(m_minerMutex);
            this->m_minerCond.wait(lock,
                [this]{ return this->m_minerStop || !this->m_minerTasks.empty(); });
            if(m_minerStop && m_minerTasks.empty())
                return;
            task = std::move(this->m_minerTasks.front());
            m_minerTasks.pop();
        }

        DoHandleAccess(task);
    }
}