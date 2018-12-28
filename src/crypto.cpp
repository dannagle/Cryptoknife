#include "crypto.h"

#include <QString>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QCryptographicHash>


#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptlib.h>

#include <pubkey.h>
#include <gfpcrypt.h>
#include <eccrypto.h>

#include <smartptr.h>
#include <crc.h>
#include <adler32.h>
#include <md2.h>
#include <md4.h>
#include <md5.h>
#include <sha.h>
#include <base64.h>
#include <tiger.h>
#include <ripemd.h>
#include <whrlpool.h>
#include <hkdf.h>
#include <blake2.h>
#include <hmac.h>
#include <ttmac.h>
#include <integer.h>
#include <pwdbased.h>
#include <filters.h>
#include <files.h>
#include <hex.h>
#include <smartptr.h>
#include <channels.h>

#include <aes.h>
#include <des.h>
#include <blowfish.h>
#include <modes.h>
#include <osrng.h>
#include <twofish.h>


#include <iostream>
#include <sstream>
#include <iomanip>

#include <validate.h>


USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

#include "globals.h"

/*

Should remove key/iv altogether and rely on PKCS5_PBKDF2_HMAC to derive...
http://stackoverflow.com/questions/23349266/is-this-encryption-method-secure


CryptoPP::AutoSeededRandomPool rnd;
rnd.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
rnd.GenerateBlock(salt, SALT_SIZE);

CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> gen;
gen.DeriveKey(key, CryptoPP::AES::MAX_KEYLENGTH, 32,
              password, pswd.length(),
              salt, SALT_SIZE,
              256);
*/
void Crypto::GenerateKeys(QHash<QString, QString> &keys, QHash<QString, QString> &IVs)
{
    QStringList ciphernames;

    ciphernames.clear();

    ciphernames <<"aes-128-cbc" << "aes-192-cbc" << "aes-256-cbc"
               <<"bf-cbc" << "des-ede3-cbc" << "des-ede-cbc"
              << "twofish" << "rc6";


    keys.clear();
    IVs.clear();


    QString ciphername;

    foreach (ciphername, ciphernames) {
        //do it

        int ivsize = CryptoPP::AES::BLOCKSIZE;
        int keylength = CryptoPP::AES::MAX_KEYLENGTH;
        int saltlength = 8; //what openssl uses

        if(ciphername == ("aes-128-cbc")) {
            keylength = CryptoPP::AES::DEFAULT_KEYLENGTH;
        }

        if(ciphername == ("aes-128-cbc")) {
            keylength = CryptoPP::AES::DEFAULT_KEYLENGTH;
        }

        if(ciphername.contains("bf")) {
            ivsize = CryptoPP::Blowfish::BLOCKSIZE;
            keylength = CryptoPP::Blowfish::MAX_KEYLENGTH;
        }

        if(ciphername == ("des-ede3-cbc")) {
            ivsize = CryptoPP::DES_EDE3::BLOCKSIZE;
            keylength = CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH;
        }

        if(ciphername == ("des-ede-cbc")) {
            ivsize = CryptoPP::DES_EDE2::BLOCKSIZE;
            keylength = CryptoPP::DES_EDE2::DEFAULT_KEYLENGTH;
        }

        if(ciphername == ("twofish")) {
            ivsize = CryptoPP::Twofish::BLOCKSIZE;
            keylength = CryptoPP::Twofish::DEFAULT_KEYLENGTH;
        }


        byte iv[ivsize];
        byte key[keylength];


        CryptoPP::AutoSeededRandomPool rnd;
        rnd.GenerateBlock(key, keylength);
        rnd.GenerateBlock(iv, ivsize);


/*
     *
     * openssl enc -aes-256-cbc -k password -nosalt -p < /dev/null
    key=5F4DCC3B5AA765D61D8327DEB882CF992B95990A9151374ABD8FF8C5A7A0FE08
    iv =B7B4372CDFBCB3D16A2631B59B509E94
    */

        QByteArray keyArray = QByteArray::fromRawData((const char *)key, keylength);
        QByteArray ivArray = QByteArray::fromRawData((const char *)iv, ivsize);


        QString keyString = QString(keyArray.toHex().toUpper());
        QString ivString = QString(ivArray.toHex().toUpper());


        QDEBUG() << ciphername << keyString << ivString ;

        keys[ciphername] = keyString;
        IVs[ciphername] = ivString;
    }




}


SecByteBlock HexDecodeString(const char *hex)
{
    StringSource ss(hex, true, new HexDecoder);
    SecByteBlock result((size_t)ss.MaxRetrievable());
    ss.Get(result, result.size());
    return result;
}

void AES_CTR_Encrypt(const char *hexKey, const char *hexIV, const char *infile, const char *outfile)
{
    SecByteBlock key = HexDecodeString(hexKey);
    SecByteBlock iv = HexDecodeString(hexIV);
    CTR_Mode<AES>::Encryption aes(key, key.size(), iv);
    FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
}


void Crypto::AES_CBC_Decrypt(const char *outfile)
{

    //AES can use 16, 24, or 32 byte keys (128, 192, and 256 bits respectively).


    QDEBUGVAR(aesKey);
    QDEBUGVAR(aesIV);

    if(aesBits < 16) {
        aesBits = 16;
    }

    int keylength = AES::DEFAULT_KEYLENGTH;
    if(aesBits == 128) {
        keylength = 16;
    }
    if(aesBits == 192) {
        keylength = 24;
    }
    if(aesBits == 256) {
        keylength = 32;
    }

    if(aesKey.size() < keylength) {
        QDEBUG() << "aesKey is wrong size" << aesKey.size() << "vs" << keylength;
        return;
    }

    if(aesIV.size() < AES::BLOCKSIZE) {
        QDEBUG() << "aesIV is wrong size" << aesIV.size() << "vs" <<  AES::BLOCKSIZE;
        return;
    }

    byte resultKey[keylength];
    byte resultIV[ AES::BLOCKSIZE] = {0};
    hexString2Bytes(aesKey, resultKey, keylength);
    hexString2Bytes(aesIV, resultIV, AES::BLOCKSIZE);


    QString tempString = bytes2HexString(resultKey, keylength);

    if(aesKey == tempString) {
        QDEBUG() << "Re-encoding is good";
    } else {
        QDEBUG() << aesKey << "vs" << tempString;
    }



    auto d = CBC_Mode<AES>::Decryption(resultKey, keylength, resultIV);

    try
        {


        // The StreamTransformationFilter removes
        //  padding as required.
        FileSource s(filename.toStdString().c_str(), true,
            new StreamTransformationFilter(d,
                 new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource

    }
    catch(const CryptoPP::Exception& e)
    {
        QDEBUG() << QString(e.what());
    }

}


void Crypto::TripleDES3_CBC_Encrypt(const char *outfile)
{

    byte iv[DES_EDE3::BLOCKSIZE];
    byte key[DES_EDE3::DEFAULT_KEYLENGTH];

    int keylength = DES_EDE3::DEFAULT_KEYLENGTH;

    hexString2Bytes(tripleDESKey, key, keylength);
    hexString2Bytes(tripleDESIV, iv, DES_EDE3::BLOCKSIZE);
    tripleDESKey = bytes2HexString(key, sizeof(key));
    tripleDESIV = bytes2HexString(iv, sizeof(iv));


    try
        {

            CBC_Mode< DES_EDE3 >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);


            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s(filename.toStdString().c_str(), true,
                new StreamTransformationFilter(e,
                    new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource

/*
            QString immediatetest = filename + ".immediatetest";


            auto d = CBC_Mode<DES_EDE3>::Decryption(key, sizeof(key), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s2(outfile, true,
                new StreamTransformationFilter(d,
                     new FileSink(immediatetest.toStdString().c_str()), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource
*/
            QDEBUG() << "The openssl command is...";

            QString outcommand; outcommand.clear();
            QTextStream out (& outcommand);
            out << "openssl des-ede3-cbc -d -K " << tripleDESKey << " -iv " << tripleDESIV <<
                   " -in " << QString(outfile) << " -out " << filename;

            QDEBUG() << "The openssl command is...";
            QDEBUG() << outcommand;

        }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //OpenSSL command looks like openssl
    //blowfish-128-cbc -d -K 41517050DF93EE6FCA8BA4DAC2B1DB17 -iv D39E88E886EDBF6D4F6E73ED4D18D443 -in testfile.txt.enc -out testfile.txt.enc.openssl.txt

    QDEBUG() << "outfile text: " << outfile << endl;



}

void Crypto::Twofish_CBC_Decrypt(const char *outfile)
{

}

void Crypto::Twofish_CBC_Encrypt(const char *outfile)
{


    byte iv[Twofish::BLOCKSIZE];
    byte key[Twofish::DEFAULT_KEYLENGTH];

    int keylength = Twofish::DEFAULT_KEYLENGTH;

    hexString2Bytes(twofishKey, key, keylength);
    hexString2Bytes(twofishIV, iv, DES_EDE2::BLOCKSIZE);

    twofishKey = bytes2HexString(key, sizeof(key));
    twofishIV = bytes2HexString(iv, sizeof(iv));

    try
        {

            CBC_Mode< Twofish >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);


            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s(filename.toStdString().c_str(), true,
                new StreamTransformationFilter(e,
                    new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource

/*
            QString immediatetest = filename + ".immediatetest";


            auto d = CBC_Mode<Twofish>::Decryption(key, sizeof(key), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s2(outfile, true,
                new StreamTransformationFilter(d,
                     new FileSink(immediatetest.toStdString().c_str()), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource
*/
            QDEBUG() << "The openssl command is does not exist for twofish";


        }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //OpenSSL command looks like openssl
    //blowfish-128-cbc -d -K 41517050DF93EE6FCA8BA4DAC2B1DB17 -iv D39E88E886EDBF6D4F6E73ED4D18D443 -in testfile.txt.enc -out testfile.txt.enc.openssl.txt

    QDEBUG() << "outfile text: " << outfile << endl;

}

void Crypto::RC6_Decrypt(const char *outfile)
{

}

void Crypto::RC6_Encrypt(const char *outfile)
{

}

void Crypto::TripleDES2_CBC_Encrypt(const char *outfile)
{

    byte iv[DES_EDE2::BLOCKSIZE];
    byte key[DES_EDE2::DEFAULT_KEYLENGTH];

    int keylength = DES_EDE2::DEFAULT_KEYLENGTH;

    hexString2Bytes(tripleDESKey, key, keylength);
    hexString2Bytes(tripleDESIV, iv, DES_EDE2::BLOCKSIZE);

    tripleDESKey = bytes2HexString(key, sizeof(key));
    tripleDESIV = bytes2HexString(iv, sizeof(iv));


    try
        {

            CBC_Mode< DES_EDE2 >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);


            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s(filename.toStdString().c_str(), true,
                new StreamTransformationFilter(e,
                    new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource

/*
            QString immediatetest = filename + ".immediatetest";


            auto d = CBC_Mode<DES_EDE2>::Decryption(key, sizeof(key), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s2(outfile, true,
                new StreamTransformationFilter(d,
                     new FileSink(immediatetest.toStdString().c_str()), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource
*/
            QDEBUG() << "The openssl command is...";

            QString outcommand; outcommand.clear();
            QTextStream out (& outcommand);
            out << "openssl des-ede-cbc -d -K " << tripleDESKey << " -iv " << tripleDESIV <<
                   " -in " << QString(outfile) << " -out " << filename;

            QDEBUG() << "The openssl command is...";
            QDEBUG() << outcommand;

        }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //OpenSSL command looks like openssl
    //blowfish-128-cbc -d -K 41517050DF93EE6FCA8BA4DAC2B1DB17 -iv D39E88E886EDBF6D4F6E73ED4D18D443 -in testfile.txt.enc -out testfile.txt.enc.openssl.txt

    QDEBUG() << "outfile text: " << outfile << endl;




}
void Crypto::TripleDES3_CBC_Decrypt(const char *outfile)
{
    QDEBUGVAR(tripleDESKey);
    QDEBUGVAR(tripleDESIV);


    byte iv[DES_EDE3::BLOCKSIZE];
    byte key[DES_EDE3::DEFAULT_KEYLENGTH];

    int keylength = DES_EDE3::DEFAULT_KEYLENGTH;


    if(tripleDESKey.size() < keylength) {
        QDEBUG() << "tripleDESKey is wrong size" << tripleDESKey.size() << "vs" << keylength;
        return;
    }

    if(tripleDESIV.size() < DES_EDE3::DEFAULT_KEYLENGTH) {
        QDEBUG() << "tripleDESIV is wrong size" << tripleDESIV.size() << "vs" <<  Blowfish::BLOCKSIZE;
        return;
    }

    hexString2Bytes(tripleDESKey, key, keylength);
    hexString2Bytes(tripleDESIV, iv, DES_EDE3::BLOCKSIZE);


    QString tempString = bytes2HexString(key, keylength);
    if(tripleDESKey == tempString) {
        QDEBUG() << "Re-encoding is good";
    } else {
        QDEBUG() << tripleDESKey << "vs" << tempString;
    }


    auto d = CBC_Mode<DES_EDE3>::Decryption(key, sizeof(key), iv);
    try
        {


        // The StreamTransformationFilter removes
        //  padding as required.
        FileSource s(filename.toStdString().c_str(), true,
            new StreamTransformationFilter(d,
                 new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource

    }
    catch(const CryptoPP::Exception& e)
    {
        QDEBUG() << QString(e.what());
    }


}

void Crypto::TripleDES2_CBC_Decrypt(const char *outfile)
{
    QDEBUGVAR(tripleDESKey);
    QDEBUGVAR(tripleDESIV);


    byte iv[DES_EDE2::BLOCKSIZE];
    byte key[DES_EDE2::DEFAULT_KEYLENGTH];

    int keylength = DES_EDE2::DEFAULT_KEYLENGTH;


    if(tripleDESKey.size() < keylength) {
        QDEBUG() << "tripleDESKey is wrong size" << tripleDESKey.size() << "vs" << keylength;
        return;
    }

    if(tripleDESIV.size() < DES_EDE2::DEFAULT_KEYLENGTH) {
        QDEBUG() << "tripleDESIV is wrong size" << tripleDESIV.size() << "vs" <<  Blowfish::BLOCKSIZE;
        return;
    }

    hexString2Bytes(tripleDESKey, key, keylength);
    hexString2Bytes(tripleDESIV, iv, DES_EDE2::BLOCKSIZE);


    QString tempString = bytes2HexString(key, keylength);
    if(tripleDESKey == tempString) {
        QDEBUG() << "Re-encoding is good";
    } else {
        QDEBUG() << tripleDESKey << "vs" << tempString;
    }


    auto d = CBC_Mode<DES_EDE2>::Decryption(key, sizeof(key), iv);
    try
        {


        // The StreamTransformationFilter removes
        //  padding as required.
        FileSource s(filename.toStdString().c_str(), true,
            new StreamTransformationFilter(d,
                 new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource

    }
    catch(const CryptoPP::Exception& e)
    {
        QDEBUG() << QString(e.what());
    }


}

void Crypto::AES_CBC_Encrypt(const char *outfile)
{

    //AES can use 16, 24, or 32 byte keys (128, 192, and 256 bits respectively).

    if(aesBits < 16) {
        aesBits = 16;
    }

    int keylength = AES::DEFAULT_KEYLENGTH;
    if(aesBits == 128) {
        keylength = 16;
    }
    if(aesBits == 192) {
        keylength = 24;
    }
    if(aesBits == 256) {
        keylength = 32;
    }



    byte key[keylength];
    byte iv[AES::BLOCKSIZE];


    hexString2Bytes(aesKey, key, keylength);
    hexString2Bytes(aesIV, iv, AES::BLOCKSIZE);

    try
        {

            CBC_Mode< AES >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);


            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s(filename.toStdString().c_str(), true,
                new StreamTransformationFilter(e,
                    new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource

            /*

            QString immediatetest = filename + ".immediatetest";


            auto d = CBC_Mode<AES>::Decryption(key, sizeof(key), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s2(outfile, true,
                new StreamTransformationFilter(d,
                     new FileSink(immediatetest.toStdString().c_str()), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource
            */

            QDEBUG() << "The openssl command is...";

            QString outcommand; outcommand.clear();
            QTextStream out (& outcommand);
            out << "openssl aes-" << aesBits << "-cbc -d -K " << aesKey << " -iv " << aesIV <<
                   " -in " << QString(outfile) << " -out " << filename;

            QDEBUG() << "The openssl command is...";
            QDEBUG() << outcommand;

        }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //OpenSSL command looks like openssl
    //aes-128-cbc -d -K 41517050DF93EE6FCA8BA4DAC2B1DB17 -iv D39E88E886EDBF6D4F6E73ED4D18D443 -in testfile.txt.enc -out testfile.txt.enc.openssl.txt

    QDEBUG() << "outfile text: " << outfile << endl;
}

void Crypto::Base64Encode(const char *infile, const char *outfile)
{
    QFile filetest(infile);
    if(!filetest.exists()) return;

    FileSource(infile, true, new Base64Encoder(new FileSink(outfile), false));
}


quint64 Crypto::Checksum(QString infile)
{
    QFile filetest(infile);
    if(!filetest.exists()) return 0;
    quint64 sum = 0;
    QByteArray data;
    quint64 mask = 0xFFFFFFFF;
    if(filetest.open(QFile::ReadOnly)) {
        while(!filetest.atEnd()) {
            data = filetest.read(1000*1000*10); // 10 megs at a time.
            QDEBUGVAR(data.size());
            for(int i = 0; i < data.size(); i++) {
                sum += ((unsigned int) data.at(i)) & 0xFF;
            }
        }

        filetest.close();

    }

    return (sum & mask);



}


void Crypto::Base64Decode(const char *infile, const char *outfile)
{
    QFile filetest(infile);
    if(!filetest.exists()) return;

    FileSource(infile, true, new Base64Decoder(new FileSink(outfile)));
}

void Crypto::HEX2Bin(const char *infile, const char *outfile)
{
    QFile filetest(infile);
    if(!filetest.exists()) return;

    FileSource(infile, true, new HexDecoder(new FileSink(outfile)));
}

void Crypto::Bin2HEX(const char *infile, const char *outfile)
{
    QFile filetest(infile);
    if(!filetest.exists()) return;

    FileSource(infile, true, new HexEncoder(new FileSink(outfile)));
}


QString Crypto::byteArrayToHex(QByteArray data)
{
    QString byte, returnString;
  //  QDEBUG() << "size is " <<data.size();

    returnString.clear();
    if(data.isEmpty())
    {
        return "";
    }

    for(int i = 0; i < data.size(); i++)
    {
        byte = QString::number((unsigned char)data.at(i) & 0xff, 16);

        if(byte.size() % 2 == 1)
        {
            byte.prepend("0");
        }
        returnString.append(byte);
        returnString.append(" ");
    }

    return returnString.trimmed().toUpper();

}



void Crypto::Blowfish_CBC_Encrypt(const char *outfile)
{

    //Blowfish does not specify bits

    int keylength = Blowfish::DEFAULT_KEYLENGTH;
    byte key[keylength];
    byte iv[Blowfish::BLOCKSIZE];

    AutoSeededRandomPool prng;
    if(blowfishKey.isEmpty()) {
        prng.GenerateBlock(key, sizeof(key));
    } else {
        hexString2Bytes(blowfishKey, key, keylength);

    }

    if(blowfishIV.isEmpty()) {
        prng.GenerateBlock(iv, sizeof(iv));
    } else {

        hexString2Bytes(blowfishIV, iv, sizeof(iv));

    }

    blowfishKey = bytes2HexString(key, sizeof(key));
    blowfishIV = bytes2HexString(iv, sizeof(iv));

    try
        {

            CBC_Mode< Blowfish >::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);


            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s(filename.toStdString().c_str(), true,
                new StreamTransformationFilter(e,
                    new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource

/*
            QString immediatetest = filename + ".immediatetest";


            auto d = CBC_Mode<Blowfish>::Decryption(key, sizeof(key), iv);

            // The StreamTransformationFilter removes
            //  padding as required.
            FileSource s2(outfile, true,
                new StreamTransformationFilter(d,
                     new FileSink(immediatetest.toStdString().c_str()), StreamTransformationFilter::PKCS_PADDING
                ) // StreamTransformationFilter
            ); // StringSource
*/
            QDEBUG() << "The openssl command is...";

            QString outcommand; outcommand.clear();
            QTextStream out (& outcommand);
            out << "openssl bf-cbc -d -K " << blowfishKey << " -iv " << blowfishIV <<
                   " -in " << QString(outfile) << " -out " << filename;

            QDEBUG() << "The openssl command is...";
            QDEBUG() << outcommand;

        }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //OpenSSL command looks like openssl
    //blowfish-128-cbc -d -K 41517050DF93EE6FCA8BA4DAC2B1DB17 -iv D39E88E886EDBF6D4F6E73ED4D18D443 -in testfile.txt.enc -out testfile.txt.enc.openssl.txt

    QDEBUG() << "outfile text: " << outfile << endl;


}

void Crypto::Blowfish_CBC_Decrypt(const char *outfile)
{


    QDEBUGVAR(blowfishKey);
    QDEBUGVAR(blowfishIV);

    int keylength = Blowfish::DEFAULT_KEYLENGTH;

    if(blowfishKey.size() < keylength) {
        QDEBUG() << "blowfishKey is wrong size" << blowfishKey.size() << "vs" << keylength;
        return;
    }

    if(blowfishIV.size() < Blowfish::BLOCKSIZE) {
        QDEBUG() << "blowfishIV is wrong size" << blowfishIV.size() << "vs" <<  Blowfish::BLOCKSIZE;
        return;
    }


    byte resultKey[keylength];
    byte resultIV[ Blowfish::BLOCKSIZE] = {0};
    hexString2Bytes(blowfishKey, resultKey, keylength);
    hexString2Bytes(blowfishIV, resultIV, Blowfish::BLOCKSIZE);


    QString tempString = bytes2HexString(resultKey, keylength);
    if(blowfishKey == tempString) {
        QDEBUG() << "Re-encoding is good";
    } else {
        QDEBUG() << blowfishKey << "vs" << tempString;
    }




    auto d = CBC_Mode<Blowfish>::Decryption(resultKey, keylength, resultIV);

    try
        {


        // The StreamTransformationFilter removes
        //  padding as required.
        FileSource s(filename.toStdString().c_str(), true,
            new StreamTransformationFilter(d,
                 new FileSink(outfile), StreamTransformationFilter::PKCS_PADDING
            ) // StreamTransformationFilter
        ); // StringSource

    }
    catch(const CryptoPP::Exception& e)
    {
        QDEBUG() << QString(e.what());
    }


}


QString Crypto::bytes2HexString(byte *resultKey, int keylength)
{
    string tempString;

    //reverse it.
    StringSource(resultKey, keylength, true,
        new HexEncoder(
            new StringSink(tempString)
        ) // HexEncoder
    ); // StringSource

    return QString(tempString.c_str());

}


QByteArray Crypto::HEXtoByteArray(QString thehex)
{
    thehex = thehex.trimmed();
     QString byte;
     QByteArray returnArray;
     QStringList hexSplit = thehex.simplified().split(" ");
     returnArray.clear();
     unsigned int foundByte = 0;
     bool ok =  false;

     if(hexSplit.size() == 1) {
         //big fat hex stream.
         if((thehex.size() > 2) && ((thehex.size() % 2) == 0)) {
             hexSplit.clear();
             for(int two = 0; two < thehex.size(); two +=2) {
                 QString append = QString(thehex[two]);
                 append.append(QString(thehex[two+1]));
                 hexSplit <<  append;
             }
         }
     }


     foreach(byte, hexSplit)
     {
         foundByte = byte.toUInt(&ok, 16);
         foundByte = foundByte & 0xff;
         if(ok)
         {
             returnArray.append(foundByte);
         }

     }

     return returnArray;

}

void Crypto::hexString2Bytes(QString keyString, byte *resultKey, int keylength)
{

    QByteArray byteData = HEXtoByteArray(keyString);
    memset(resultKey, 0, keylength);
    for(int i=0; i<byteData.size(); i++) {
        resultKey[i] = ((byte) (byteData.at(i) & 0xff));
    }

}



void Crypto::doHash()
{

    if(filename.isEmpty()) {
        return;
    }

    if(!QFile::exists(filename)) {

        return;
    }

    QFileInfo fileInfo(filename);

    if(!fileInfo.isFile()) {
        return;
    }


    ChannelSwitch cs;
    Weak::MD5 md5;
    Weak::MD2 md2;
    Weak::MD4 md4;

    SHA1 sha1;
    SHA224 sha224;
    SHA256 sha256;
    SHA384 sha384;
    SHA512 sha512;

    QString theFile = filename;
    QFile testFile (theFile);
    QFileInfo testFileInfo (theFile);

    if(testFile.exists()) {
        QDEBUG() << "Exists";
    } else {
        QDEBUG() << "NOT Exists";
    }


    string message; message.clear();

    string ssha1, ssha224, ssha256, ssha384, ssha512, smd5, smd2, smd4;

    ssha1.clear(); ssha224.clear(); ssha256.clear(); ssha384.clear(); ssha512.clear();
    smd5.clear(); smd2.clear(); smd4.clear();


    string filenameStd = string(theFile.toLocal8Bit().toStdString());
    filenameStd = testFileInfo.canonicalFilePath().toLocal8Bit().toStdString();


    FileSource file(filenameStd.c_str(), true, new StringSink(message));


    HashFilter fsha1(sha1, new HexEncoder(new StringSink(ssha1)));
    //wxLogMessage("sha1 ready at %ld ms", sw.Time());

    HashFilter fsha224(sha224, new HexEncoder(new StringSink(ssha224)));
    //wxLogMessage("sha224 ready at %ld ms", sw.Time());

    HashFilter fsha256(sha256, new HexEncoder(new StringSink(ssha256)));
    //wxLogMessage("sha256 ready at %ld ms", sw.Time());

    HashFilter fsha384(sha384, new HexEncoder(new StringSink(ssha384)));
    //wxLogMessage("sha256 ready at %ld ms", sw.Time());

    HashFilter fsha512(sha512, new HexEncoder(new StringSink(ssha512)));
    //wxLogMessage("sha512 ready at %ld ms", sw.Time());

    HashFilter fmd5(md5, new HexEncoder(new StringSink(smd5)));
    //wxLogMessage("md5 ready at %ld ms", sw.Time());


    HashFilter fmd2(md2, new HexEncoder(new StringSink(smd2)));
    //wxLogMessage("md2 ready at %ld ms", sw.Time());


    HashFilter fmd4(md4, new HexEncoder(new StringSink(smd4)));
    //wxLogMessage("md4 ready at %ld ms", sw.Time());



    if (doMD5) cs.AddDefaultRoute(fmd5);
    if (dosha1) cs.AddDefaultRoute(fsha1);
    if (dosha224) cs.AddDefaultRoute(fsha224);
    if (dosha384) cs.AddDefaultRoute(fsha384);
    if (dosha256) cs.AddDefaultRoute(fsha256);
    if (dosha512) cs.AddDefaultRoute(fsha512);

    if (domd2) cs.AddDefaultRoute(fmd2);
    if (domd4) cs.AddDefaultRoute(fmd4);


    StringSource ss(message, true /*pumpAll*/, new Redirector(cs));
    //wxLogMessage("file finished at %ld ms", sw.Time());


    std::stringstream streambuffer;

    if (domd2) streambuffer << "MD2: " << smd2 << endl;
    if (domd4) streambuffer << "MD4: " << smd4 << endl;
    if (doMD5) streambuffer << "MD5: " << smd5 << endl;
    if (dosha1) streambuffer << "SHA-1: " << ssha1 << endl;
    if (dosha224) streambuffer << "SHA-224: " << ssha224 << endl;
    if (dosha256) streambuffer << "SHA-256: " << ssha256 << endl;
    if (dosha384) streambuffer << "SHA-384: " << ssha384 << endl;
    if (dosha512) streambuffer << "SHA-512: " << ssha512 << endl;


    QDEBUG() << streambuffer.str().c_str();
    result = QString(streambuffer.str().c_str());


}


Crypto::Crypto()
{

    result.clear();
    filename.clear();

    doMD5 = true;
    dosha1  = true;
    dosha224  = true;
    dosha256  = true;
    dosha384  = true;
    dosha512  = true;


    domd4  = true;
    domd2  = true;


    doAESCBC = false;
    aesBits = 16;
    aesKey.clear();
    aesIV.clear();




}
