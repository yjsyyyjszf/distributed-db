#include <httplib.h>
#include <iostream>
#include <string>
#include "json.hpp"
#include "../common/crypto.hpp"
#include "../common/network_api.hpp"

using namespace httplib;
using namespace crypto;
using json = nlohmann::json;

class User
{
public:
    User(const char* ip, int port):
        m_client{ip, port}
    {
        m_client.enable_server_certificate_verification(false);
    }

    void CompoundIdentity()
    {
        std::cout << "Enter user id" << std::endl;
        std::cin >> m_id;

        m_userKey.GeneratePair();
        m_encKey.GenerateKey(m_userKey.GetPrivateKey());

        std::stringstream ss;
        ss << "/createIdentity?userId=" << m_id << "&"
           << "userPubSigKey=" << m_userKey.GetPublicKey() << "&"
        //    << "userPubSigKey=" << m_userKey.GetPrivateKey() << "&"
           << "encKey=" << m_encKey.GetKey();
        auto res = m_client.Get(ss.str().c_str());
        if (res) 
        {
            if (res->status != 200)
            {
                std::cerr << res->body << std::endl;
                return;
            }
            m_serviceKey.SetPublicKey(res->body);
            // m_serviceKey.SetPrivateKey(res->body);
        } 
        else 
        {
            std::cout << "Failed response!\n";
            auto result = m_client.get_openssl_verify_result();
            if (result) 
            {
                std::cout << "verify error: " << X509_verify_cert_error_string(result) << std::endl;
            }
        }
    }

    void HandleAccessTx(json& rw)
    {
        rw["userKey"] = m_userKey.GetPublicKey();
        rw["serviceKey"] = m_serviceKey.GetPublicKey();
        std::set<in_port_t> ports;
        FillP2pPortSet(1235, ports);
        for (const auto port : ports)
        {
            sockpp::tcp_connector conn{{"localhost", port}};
            if (!conn) continue;
            SendRequest(conn, NetworkRequest::HandleAccess);
            rw["salt"] = ReadJsonMessage(conn)["salt"].get<std::string>();
            SignHandleAccessMessage(rw, m_userKey.GetPrivateKey());
            WriteJsonMessage(conn, rw);
        }
    }

    void HandleData(const std::string& data)
    {
        json d;
        d["userKey"] = m_userKey.GetPublicKey();
        d["serviceKey"] = m_serviceKey.GetPublicKey();
        d["data"] = m_encKey.Encrypt(data);
        d["from"] = "user";
        d["oper"] = "write";
        std::set<in_port_t> ports;
        FillP2pPortSet(1235, ports);
        for (const auto port : ports)
        {
            httplib::Client client("localhost", port);
            sockpp::tcp_connector conn{{"localhost", port}};
            if (!conn) continue;
            SendRequest(conn, NetworkRequest::HandleData);
            d["salt"] = ReadJsonMessage(conn).at("salt").get<std::string>();
            SignHandleDataMessage(d, m_userKey.GetPrivateKey());
            WriteJsonMessage(conn, d);
            //ReadJsonMessage(conn);
        }
    }

    void Interface()
    {
        Server server;

        server.Post("/interfaceData", [this](const Request& req, Response& res) {
            std::cout << "interfaceData\n" << req.body << std::endl;
            HandleData(req.body);
            res.status = 200;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Methods", "POST");
        });

        server.Post("/interfaceAccess", [this](const Request& req, Response& res) {
            auto j = json::parse(req.body);
            std::cout << "interfaceAccess\n" << j << std::endl;
            HandleAccessTx(j);
            res.status = 200;
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Methods", "POST");
        });

        server.listen("192.168.0.107", 4000);
    }
private:
    SSLClient m_client;

    std::string m_id;
    RsaKeyPairSig m_serviceKey;
    RsaKeyPairSig m_userKey;
    AesKey m_encKey;
};

int main(int argc, char* argv[])
{
    User user{"localhost", 1488};

    user.CompoundIdentity();
    user.Interface();
    // json j;
    // while(true)
    // {
    //     std::string cmd;
    //     std::cout <<" Enter command (access/data)\n";
    //     std::cin >> cmd;
    //     if (cmd == "access")
    //     {
    //         std::cout << "enter read rights\n";
    //         bool flag;
    //         std::cin  >> flag;
    //         j["readRights"] = flag;
    //         std::cout << "enter write rights\n";
    //         std::cin  >> flag;
    //         j["writeRights"] = flag;
    //         user.HandleAccessTx(j);
    //     }
    //     else if (cmd == "data")
    //     {
    //         std::cout << "enter data\n";
    //         std::string data;
    //         std::cin >> data;
    //         user.HandleData(data);
    //     }
    // }

    return 0;
}