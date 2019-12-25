#pragma once

#include <set>
#include <string>
#include <stdexcept>
#include "json.hpp"
#include "../common/crypto.hpp"
#include <sockpp/tcp_connector.h>

using json = nlohmann::json;
using namespace crypto;

enum class NetworkRequest: uint16_t
{
    GetAllNodes,
    AddNode,
    PostBlockchain,
    HandleAccess,
    HandleData
};

template<typename SockType>
void SendRequest(SockType& sock, NetworkRequest req)
{
    auto buf = htons(static_cast<uint16_t>(req));
    if (sock.write_n(&buf, sizeof(buf)) != sizeof(buf))
    {
        std::cerr << sock.last_error_str() << std::endl;
    }
}

template<typename SockType>
json ReadJsonMessage(SockType& sock)
{
    uint32_t size = 0;

    if (sock.read_n(&size, sizeof(size)) != sizeof(size))
    {
        std::cerr << sock.last_error_str() << std::endl;
        return json();
    }
    size = ntohl(size);

    std::string msg(size, 0);
    if (sock.read_n(&msg[0], size) != size)
    {
        std::cerr << sock.last_error_str() << std::endl;
        return json();
    }

    return json::parse(msg);
}

template<typename SockType>
void WriteJsonMessage(SockType& sock, const json& j)
{
    std::string msg = j.dump();
    uint32_t size = msg.size();
    uint32_t sizeBuf = htonl(msg.size());

    if (sock.write_n(&sizeBuf, sizeof(sizeBuf)) != sizeof(sizeBuf))
    {
        // std::cerr << sock.last_error_str() << std::endl;
        return;
    }
    if (sock.write_n(&msg[0], size) != size)
    {
        // std::cerr << sock.last_error_str() << std::endl;
    }
}

inline bool FillP2pPortSet(in_port_t otherPort, std::set<in_port_t>& portSet)
{
    sockpp::tcp_connector conn{{"192.168.43.128", otherPort}};
    if (!conn)
    {
        std::cerr << "Error connecting to node at port " << otherPort << "\n\t"
                << conn.last_error_str() << std::endl;
        return false;
    }
    SendRequest(conn, NetworkRequest::GetAllNodes);

    json j = ReadJsonMessage(conn);
    auto result = j.get<std::set<in_port_t>>();
    // std::cout << "Found nodes " + j.dump() << std::endl;
    portSet.insert(otherPort);
    for (auto port : result)
    {
        if (portSet.count(port) == 1)
        {
            continue;
        }

        portSet.insert(port);
        FillP2pPortSet(port, portSet);
    }

    return true;
}

inline std::string SignHandleAccessMessage(json& j, const std::string& prKey)
{
    std::string toSign = j["userKey"].get<std::string>() + 
                         j["serviceKey"].get<std::string>() + 
                         j["salt"].get<std::string>() +
                         std::to_string(j["readRights"].get<bool>()) +
                         std::to_string(j["writeRights"].get<bool>());
    return j["signature"] = SignMessage(toSign, prKey);
}

inline bool VerifyHandleAccessMessage(const json& j)
{
    std::string toSign = j["userKey"].get<std::string>() + 
                         j["serviceKey"].get<std::string>() + 
                         j["salt"].get<std::string>() +
                         std::to_string(j["readRights"].get<bool>()) +
                         std::to_string(j["writeRights"].get<bool>());
    return CheckSign(toSign, j.at("userKey").get<std::string>(), j.at("signature").get<std::string>());
}


inline std::string SignHandleDataMessage(json& j, const std::string& prKey)
{
    std::string toSign = j["userKey"].get<std::string>() + 
                         j["serviceKey"].get<std::string>() + 
                         j["salt"].get<std::string>() +
                         j["data"].get<std::string>() + 
                         j["oper"].get<std::string>() + 
                         j["from"].get<std::string>();
    return j["signature"] = SignMessage(toSign, prKey);
}

inline bool VerifyHandleDataMessage(const json& j)
{
    std::string toSign = j["userKey"].get<std::string>() + 
                         j["serviceKey"].get<std::string>() + 
                         j["salt"].get<std::string>() +
                         j["data"].get<std::string>() + 
                         j["oper"].get<std::string>() + 
                         j["from"].get<std::string>();
    std::string key;
    if (j["from"].get<std::string>() == "user")
        key = j.at("userKey").get<std::string>();
    else if (j["from"].get<std::string>() == "service")
        key = j.at("serviceKey").get<std::string>();
    else 
    {
        std::cerr << "Source is not allowed " << j["from"].get<std::string>() << std::endl;
        return false;
    }
    return CheckSign(toSign, key, j.at("signature").get<std::string>());
}

inline std::string GetIdentityHashFromMessage(const json& j)
{
    return crypto::Sha256(j.at("userKey").get<std::string>() + 
                          j.at("serviceKey").get<std::string>());
}