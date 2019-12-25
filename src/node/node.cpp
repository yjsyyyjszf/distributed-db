#include <iostream>
#include "network.hpp"

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " thisPort otherPort" << std::endl;
        return -1;
    }
    int thisPort  = std::stoi(argv[1]);
    int otherPort = std::stoi(argv[2]);
    bool initial = otherPort < 0;

    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;

    leveldb::Status status = leveldb::DB::Open(options, "/tmp/datastorage_" + std::to_string(thisPort), &db);
    if (!status.ok())
    {
        std::cerr << "Failed to create database: " << status.ToString() << std::endl;
        return -1;
    }

    sockpp::socket_initializer sockInit;
    Network network{thisPort, initial, db};
    if (!initial)
    {
        if (!network.Join(otherPort)) 
        {
            std::cerr << "Failed to join any nodes" << std::endl;
            return -1;
        }
    }

    if (!network.ValidateBlockchain())
    {
        std::cerr << "Broken initial state" << std::endl;
        return -1;
    }
    network.Listen();

    delete db;

    return 0;
}