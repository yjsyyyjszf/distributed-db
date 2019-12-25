#include <map>
#include <set>
#include <thread>
#include <string>
#include <iostream>
#include "json.hpp"
#include <httplib.h>
#include "../common/crypto.hpp"
#include "../common/network_api.hpp"

using namespace crypto;
using namespace httplib;
using json = nlohmann::json;

struct UserId
{
    std::string id;
    RsaKeyPairSig serviceKey;
    RsaKeyPairSig userKey;
    AesKey encKey;
};

class Service
{
public:
    Service(): m_server{"cert.pem", "key.pem"} {}
    void Run();

    std::string HandleData(const std::string& userId)
    {
        auto& user = m_users.at(userId);
        json d;
        d["userKey"] = user.userKey.GetPublicKey();
        d["serviceKey"] = user.serviceKey.GetPublicKey();
        d["data"] = "";
        d["from"] = "service";
        d["oper"] = "read";
        std::set<in_port_t> ports;
        FillP2pPortSet(1235, ports);
        std::map<std::string, unsigned int> values;
        for (const auto port : ports)
        {
            sockpp::tcp_connector conn{{"localhost", port}};
            SendRequest(conn, NetworkRequest::HandleData);
            d["salt"] = ReadJsonMessage(conn)["salt"].get<std::string>();
            SignHandleDataMessage(d, user.serviceKey.GetPrivateKey());
            WriteJsonMessage(conn, d);
            auto res = ReadJsonMessage(conn);
            values[res["data"].get<std::string>()] += 1;
        }
        auto x = std::max_element(values.begin(), values.end(),
            [](const auto& p1, const  auto& p2) {
                return p1.second < p2.second;
            });
        if (x->second < values.size()/2 + 1)
            return "";
        if (x->first == "Access denied!")
            return "Access denied!";
        return user.encKey.Decrypt(x->first);
    }

    void Interface()
    {
        Server server;

        server.Get("/interfaceData", [this](const Request& req, Response& res) {
            std::cout << "interfaceData\n" << req.body << std::endl;
            json ret;
            for (const auto& it : m_users)
            {
                ret[it.first] = HandleData(it.first);
            }
            // std::cout << ret << std::endl;
            res.set_content(ret.dump(), "text/plain");
            res.status = 200;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Methods", "GET");
        });

        server.listen("192.168.43.128", 4001);
    }
private:    
    std::map<std::string, UserId> m_users;

    httplib::SSLServer m_server;
};

void Service::Run()
{
    using namespace httplib;

    m_server.Get("/createIdentity", [this](const Request& req, Response& res) {
        res.status = 400;

        auto userId = req.get_param_value("userId");
        if (userId == "")
        {
            res.set_content("No user id!", "text/plain");
            return;
        }
        else if (m_users.count(userId) == 1)
        {
            res.set_content("User already exists!", "text/plain");
            return;
        }

        auto userPubSigKey = req.get_param_value("userPubSigKey");
        if (userPubSigKey == "")
        {
            res.set_content("No user pub sig key!", "text/plain");
            return;
        }

        auto encKey = req.get_param_value("encKey");
        if (encKey == "")
        {
            res.set_content("No encription key!", "text/plain");
            return;
        }
        // m_users[userId] = UserId{};
        m_users[userId].id = userId;
        m_users[userId].serviceKey.GeneratePair();
        m_users[userId].userKey.SetPublicKey(userPubSigKey);
        // id.userKey.SetPrivateKey(userPubSigKey);
        m_users[userId].encKey.SetKey(encKey);

        res.status = 200;
        res.set_content(m_users[userId].serviceKey.GetPublicKey(), "text/plain");
        // res.set_content(id.serviceKey.GetPrivateKey(), "text/plain");
        std::cout << "User " << userId << " has been added!\n";
    });

    m_server.listen("192.168.43.128", 1488);
}

int main(int argc, char* argv[])
{
    using namespace httplib;

    Service service;
    // service.Run();
    std::thread identity(&Service::Run, &service);
    service.Interface();


    return 0;
}