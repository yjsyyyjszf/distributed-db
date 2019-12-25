#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <cassert>
#include <algorithm>
#include <cmath>
#include <cstring>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/stat.h>

#include "base64.hpp"

namespace crypto
{

inline std::string Sha256(const std::string& str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

inline unsigned char* Str(const std::string& s)
{
    return reinterpret_cast<unsigned char*>(const_cast<char*>(s.c_str()));
    
}

class RsaKeyPair
{
public:
    RsaKeyPair():
        hasPrivate(false),
        hasPublic(false),
        m_rsa(nullptr)
    {
        m_rsa = RSA_new();
        RAND_seed(m_rsa, sizeof(&m_rsa));
    }

    RsaKeyPair(RsaKeyPair& k) = delete;
    RsaKeyPair(RsaKeyPair&& k) = delete;
    RsaKeyPair& operator= (RsaKeyPair& k) = delete; 
    RsaKeyPair& operator= (RsaKeyPair&& k) = delete; 

    ~RsaKeyPair()
    {
        RSA_free(m_rsa);
    }

    int GeneratePair()
    {
        BIGNUM* e = nullptr;
        e = BN_new();
        BN_set_word(e, RSA_F4);
        auto ret = RSA_generate_key_ex(m_rsa, 2048, e, NULL);
        hasPublic = ret;
        hasPrivate = ret;
        BN_free(e);
        return ret;
    }

    std::string Encrypt(const std::string& m)
    {
        std::size_t rsaBlockSize = RSA_size(m_rsa);
        if (!hasPublic || m.size() > rsaBlockSize)
            return "";
        unsigned char* to = reinterpret_cast<unsigned char*>(calloc(1, rsaBlockSize));
        std::string ret = "";
        RSA_public_encrypt(m.size(), Str(m), to, m_rsa, RSA_PKCS1_PADDING);
        ret = base64_encode(to, rsaBlockSize);
        free(to);
        return ret;
    }

    std::string Decrypt(const std::string& mEnc)
    {
        if (!hasPrivate)
            return "";
        auto rsaBlockSize = RSA_size(m_rsa);
        auto m = base64_decode(mEnc);
        std::size_t nBlocks = std::ceil( (double) m.size() / rsaBlockSize );
        if (nBlocks != 1)
            return "";
        unsigned char* to = reinterpret_cast<unsigned char*>(calloc(1, rsaBlockSize));
        RSA_private_decrypt(rsaBlockSize, Str(m), to, m_rsa, RSA_PKCS1_PADDING);
        std::string ret = reinterpret_cast<char*>(to);
        free(to);
        return ret;
    }

    std::string GetPublicKey()
    {
        if (!hasPublic)
            return std::string("");
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(bio, m_rsa);
        auto pemKeySize = BIO_pending(bio);
        std::string key(pemKeySize, '0');
        BIO_read(bio, Str(key), pemKeySize);
        BIO_free(bio);
        std::replace(key.begin(), key.end(), '=', '@');
        return key;
    }

    std::string GetPrivateKey()
    {
        if (!hasPrivate)
            return std::string("");
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(bio, m_rsa, nullptr, nullptr, 0, nullptr, nullptr);
        auto pemKeySize = BIO_pending(bio);
        std::string key(pemKeySize, '0');
        BIO_read(bio, Str(key), pemKeySize);
        BIO_free(bio);
        std::replace(key.begin(), key.end(), '=', '@');
        return key;
    }
    
    void SetPublicKey(std::string k)
    {
        std::replace(k.begin(), k.end(), '@', '=');
        BIO* bio = BIO_new(BIO_s_mem());
        BIO_write(bio, Str(k), k.size());
        PEM_read_bio_RSAPublicKey(bio, &m_rsa, nullptr, nullptr);
        hasPublic = true;
        BIO_free(bio);
    }

    void SetPrivateKey(std::string k)
    {
        std::replace(k.begin(), k.end(), '@', '=');
        BIO* bio = BIO_new(BIO_s_mem());
        BIO_write(bio, Str(k), k.size());
        PEM_read_bio_RSAPrivateKey(bio, &m_rsa, nullptr, nullptr);
        hasPrivate = true;
        BIO_free(bio);
    }

private:
    bool hasPrivate;
    bool hasPublic;
    RSA* m_rsa;
};

class RsaKeyPairSig
{
public:
    int GeneratePair()
    {
        return kp.GeneratePair();
    }

    std::string Sign(const std::string& m)
    {
        return kp.Encrypt(Sha256(m));
    }

    bool Check(const std::string& m, const std::string& sig)
    {
        return kp.Decrypt(sig) == Sha256(m);
    }

    std::string GetPublicKey()
    {
        return kp.GetPrivateKey();
    }

    std::string GetPrivateKey()
    {
        return kp.GetPublicKey();
    }
    
    void SetPublicKey(const std::string& k)
    {
        kp.SetPrivateKey(k);
    }

    void SetPrivateKey(const std::string& k)
    {
        kp.SetPublicKey(k);
    }


private:
    RsaKeyPair kp;
};

class AesKey
{
public:
    AesKey():
        m_en(nullptr),
        m_de(nullptr)
    {
        m_en = EVP_CIPHER_CTX_new();
        m_de = EVP_CIPHER_CTX_new();
    }

    ~AesKey()
    {
        EVP_CIPHER_CTX_free(m_en);
        EVP_CIPHER_CTX_free(m_de);
    }

    int GenerateKey(const std::string& keyData)
    {
        EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), reinterpret_cast<unsigned char*>(&m_en), Str(keyData), keyData.size(), 5, m_key, m_iv);
        EVP_CIPHER_CTX_init(m_en);
        EVP_CIPHER_CTX_init(m_de);
        EVP_EncryptInit_ex(m_en, EVP_aes_256_cbc(), NULL, m_key, m_iv);
        EVP_DecryptInit_ex(m_de, EVP_aes_256_cbc(), NULL, m_key, m_iv);
        return 1;
    }

    int SetKey(const std::string& key)
    {
        auto k = base64_decode(key);
        std::memcpy(m_key, k.data(), 64);
        EVP_CIPHER_CTX_init(m_en);
        EVP_CIPHER_CTX_init(m_de);
        EVP_EncryptInit_ex(m_en, EVP_aes_256_cbc(), nullptr, m_key, m_iv);
        EVP_DecryptInit_ex(m_de, EVP_aes_256_cbc(), nullptr, m_key, m_iv);
        return 1;
    }

    std::string GetKey()
    {
        return base64_encode(m_key, 64); 
    }

    std::string Encrypt(const std::string& m)
    {
        int c_len = m.size() + S_BLKSIZE;
        int f_len = 0;
        unsigned char* to = reinterpret_cast<unsigned char*>(calloc(c_len, sizeof(*to)));
        EVP_EncryptInit_ex(m_en, nullptr, nullptr, nullptr, nullptr);
        EVP_EncryptUpdate(m_en, to, &c_len, Str(m.data()), m.size());
        EVP_EncryptFinal_ex(m_en, to + c_len, &f_len);
        return base64_encode(to, c_len + f_len);

    }

    std::string Decrypt(const std::string& m)
    {
        auto mes = base64_decode(m);
        int c_len = mes.size();
        int f_len = 0;
        unsigned char* to = reinterpret_cast<unsigned char*>(calloc(mes.size(), sizeof(*to)));
        EVP_DecryptInit_ex(m_de, nullptr, nullptr, nullptr, nullptr);
        EVP_DecryptUpdate(m_de, to, &c_len, Str(mes.data()), mes.size());
        EVP_DecryptFinal_ex(m_de, to+c_len, &f_len);
        std::string ret = reinterpret_cast<char*>(to);
        free(to);
        return ret.substr(0, c_len+f_len);
    }
private:
    unsigned char m_key[32];
    unsigned char m_iv[32];

    EVP_CIPHER_CTX* m_en;
    EVP_CIPHER_CTX* m_de;

};

inline std::string SignMessage(const std::string& m, const std::string& key)
{
    RsaKeyPairSig kp;
    kp.SetPrivateKey(key);
    return kp.Sign(m);
}

inline bool CheckSign(const std::string& m, const std::string& key, const std::string& sig)
{
    RsaKeyPairSig kp;
    kp.SetPublicKey(key);
    return kp.Check(m, sig);
}


inline void TestEncr()
{
    RsaKeyPair p;
    p.GeneratePair();
    std::cout << p.GetPublicKey() << std::endl;
    std::cout << p.GetPrivateKey() << std::endl;
    std::string a = "encrypt me please PCAC";
    std::string encA = p.Encrypt(a);
    std::cout << "original = " << a << std::endl;
    std::cout << "encr = " << encA << std::endl;
    std::string b = p.Decrypt(encA);
    std::cout << "decrypt = "<<  b << std::endl;
    assert(a==b);


    RsaKeyPair p2;
    p2.SetPublicKey(p.GetPublicKey() );
    encA = p2.Encrypt(a);
    std::cout << "original = " << a << std::endl;
    std::cout << "encr = " << encA << std::endl;
    b = p.Decrypt(encA);
    std::cout << "decrypt = "<<  b << std::endl;
    assert(a==b);

    RsaKeyPair p3;
    p3.SetPrivateKey(p.GetPrivateKey());
    encA = p.Encrypt(a);
    std::cout << "original = " << a << std::endl;
    std::cout << "encr = " << encA << std::endl;
    b = p3.Decrypt(encA);
    std::cout << "decrypt = "<<  b << std::endl;
    assert(a==b);

    RsaKeyPairSig sp;
    sp.GeneratePair();
    std::cout << "sign start  " << std::endl;
    std::string sigA = sp.Sign(a);
    std::cout << "sign = " << sigA << std::endl;
    assert(sp.Check(a, sigA) == true );
    assert(sp.Check(a, sp.Sign(encA)) == false );
    std::cerr << "here\n";

    AesKey k;
    k.GenerateKey("hi");
    std::cout << k.GetKey() << std::endl;
    AesKey k2;
    k2.SetKey(k.GetKey());
    std::cout << k2.GetKey() << std::endl;
    assert(k.GetKey() == k2.GetKey());
    std::cerr <<"hi bich!\n";
    encA = k.Encrypt(a);
    std::cout << "original = " << a << std::endl;
    std::cout << "encr = " << encA << std::endl;
    b = k2.Decrypt(encA);
    std::cout << "decrypt = "<<  b << std::endl;
    std::cout << a.size() << " " << b.size() << std::endl;
    assert(a==b);
}

}