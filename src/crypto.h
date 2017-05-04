#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>


typedef unsigned char byte;


class Crypto
{
public:
    Crypto();

    QString filename;
    QString result;


    bool doMD5;
    bool  dosha1;
    bool  dosha224;
    bool  dosha256;
    bool  dosha384;
    bool  dosha512;

    bool  domd4;
    bool  domd2;


    bool doAESCBC;
    int aesBits;
    QString aesKey;
    QString aesIV;

    QString blowfishKey;
    QString blowfishIV;

    QString tripleDESKey;
    QString tripleDESIV;

    QString twofishKey;
    QString twofishIV;

    QString rc6Key;
    QString rc6IV;

    void doHash();
    void AES_CBC_Encrypt(const char *outfile);
    static void Base64Encode(const char *infile, const char *outfile);
    static void Base64Decode(const char *infile, const char *outfile);
    static void HEX2Bin(const char *infile, const char *outfile);
    static void Bin2HEX(const char *infile, const char *outfile);
    void AES_CBC_Decrypt(const char *outfile);
    static QString byteArrayToHex(QByteArray data);


    void Blowfish_CBC_Encrypt(const char *outfile);
    void Blowfish_CBC_Decrypt(const char *outfile);

    void hexString2Bytes (QString keyString, byte * resultKey, int keylength);


    void TripleDES2_CBC_Encrypt(const char *outfile);
    void TripleDES2_CBC_Decrypt(const char *outfile);
    static QString bytes2HexString(byte *resultKey, int keylength);
    void TripleDES3_CBC_Decrypt(const char *outfile);
    void TripleDES3_CBC_Encrypt(const char *outfile);
    void Twofish_CBC_Decrypt(const char *outfile);
    void Twofish_CBC_Encrypt(const char *outfile);
    void RC6_Decrypt(const char *outfile);
    void RC6_Encrypt(const char *outfile);
    static QByteArray HEXtoByteArray(QString thehex);
    static void GenerateKeys(QHash<QString, QString> &keys, QHash<QString, QString> &IVs);
    static quint64 Checksum(QString infile);
};

#endif // CRYPTO_H
