// pem.h - PEM read and write routines. Written and placed in the public domain by Jeffrey Walton
//         Copyright assigned to the Crypto++ project.
//
// Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2) licensed
// under the Boost Software License 1.0, while the individual files in the compilation
// are all public domain.

///////////////////////////////////////////////////////////////////////////
// For documentation on the PEM read and write routines, see
//   http://www.cryptopp.com/wiki/PEM_Pack
///////////////////////////////////////////////////////////////////////////

// Why Not Specialize Function Templates?
//   http://www.gotw.ca/publications/mill17.htm

#ifndef CRYPTOPP_PEM_H
#define CRYPTOPP_PEM_H

#include "pubkey.h"
#include "eccrypto.h"
#include "integer.h"
#include "dsa.h"
#include "rsa.h"

NAMESPACE_BEGIN(CryptoPP)

// Attempts to read a PEM encoded key or parameter. If there are multiple keys or parameters, then only
//   the first is read. If `trimTrailing` is true, then trailing whitespace is trimmed from the source
//   BufferedTransformation. The destination BufferedTransformation will have one line ending if it was
//   present in source.
// PEM_NextObject will parse an invalid object. For example, it will parse a key or parameter with
//   `-----BEGIN FOO-----` and `-----END BAR-----`. The parser only looks for BEGIN and END (and the
//   dashes). The malformed input will be caught later when a particular key or parameter is parsed.
// On failure, InvalidDataFormat is thrown.
void PEM_NextObject(BufferedTransformation& src, BufferedTransformation& dest, bool trimTrailing=true);

// PEM types we understand. We can read and write many of them, but not all of them.
//   http://stackoverflow.com/questions/5355046/where-is-the-pem-file-format-specified
enum PEM_Type { PEM_PUBLIC_KEY = 1, PEM_PRIVATE_KEY,
    PEM_RSA_PUBLIC_KEY, PEM_RSA_PRIVATE_KEY, PEM_RSA_ENC_PRIVATE_KEY,
    PEM_DSA_PUBLIC_KEY, PEM_DSA_PRIVATE_KEY, PEM_DSA_ENC_PRIVATE_KEY,
    PEM_EC_PUBLIC_KEY, PEM_ECDSA_PUBLIC_KEY, PEM_EC_PRIVATE_KEY, PEM_EC_ENC_PRIVATE_KEY,
    PEM_EC_PARAMETERS, PEM_DH_PARAMETERS, PEM_DSA_PARAMETERS,
    PEM_X509_CERTIFICATE, PEM_REQ_CERTIFICATE, PEM_CERTIFICATE,
    PEM_UNSUPPORTED = 0xFFFFFFFF };

// Attempts to determine the type of key or parameter
PEM_Type PEM_GetType(const BufferedTransformation& bt);

//////////////////////////////////////////////////////////////////////////////////////////

// Begin the Read routines. Internally, the read routines call PEM_NextObject.
// On failure, any number of Crypto++ exceptions are thrown. No custom
// exceptions are thrown.

void PEM_Load(BufferedTransformation& bt, RSA::PublicKey& rsa);
void PEM_Load(BufferedTransformation& bt, RSA::PrivateKey& rsa);
void PEM_Load(BufferedTransformation& bt, RSA::PrivateKey& rsa,
              const char* password, size_t length);

void PEM_Load(BufferedTransformation& bt, DSA::PublicKey& dsa);
void PEM_Load(BufferedTransformation& bt, DSA::PrivateKey& dsa);
void PEM_Load(BufferedTransformation& bt, DSA::PrivateKey& dsa,
              const char* password, size_t length);

void PEM_Load(BufferedTransformation& bt, DL_PublicKey_EC<ECP>& ec);
void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<ECP>& ec);
void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<ECP>& ec,
              const char* password, size_t length);

void PEM_Load(BufferedTransformation& bt, DL_PublicKey_EC<EC2N>& ec);
void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<EC2N>& ec);
void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<EC2N>& ec,
              const char* password, size_t length);

void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<ECP>::PrivateKey& ecdsa);
void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<ECP>::PrivateKey& ecdsa,
              const char* password, size_t length);

void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<EC2N>::PrivateKey& ecdsa);
void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<EC2N>::PrivateKey& ecdsa,
              const char* password, size_t length);

void PEM_Load(BufferedTransformation& bt, DL_GroupParameters_DSA& params);
void PEM_Load(BufferedTransformation& bt, DL_GroupParameters_EC<ECP>& params);
void PEM_Load(BufferedTransformation& bt, DL_GroupParameters_EC<EC2N>& params);

void PEM_DH_Load(BufferedTransformation& bt, Integer& p, Integer& g);
void PEM_DH_Load(BufferedTransformation& bt, Integer& p, Integer& q, Integer& g);

//////////////////////////////////////////////////////////////////////////////////////////

// Begin the Write routines. The write routines always write the "named curve"
//   (i.e., the OID of secp256k1) rather than the domain paramters. This is because
//   RFC 5915 specifies the format. In addition, OpenSSL cannot load and utilize
//   an EC key with a non-named curve into a server.
// For encrpted private keys, the algorithm should be a value like
//   `AES-128-CBC`. See pem-rd.cpp and pem-wr.cpp for the values that are recognized.
// On failure, any number of Crypto++ exceptions are thrown. No custom exceptions
//   are thrown.

void PEM_Save(BufferedTransformation& bt, const RSA::PublicKey& rsa);
void PEM_Save(BufferedTransformation& bt, const RSA::PrivateKey& rsa);
void PEM_Save(BufferedTransformation& bt, RandomNumberGenerator& rng, const RSA::PrivateKey& rsa,
              const std::string& algorithm, const char* password, size_t length);

void PEM_Save(BufferedTransformation& bt, const DSA::PublicKey& dsa);
void PEM_Save(BufferedTransformation& bt, const DSA::PrivateKey& dsa);
void PEM_Save(BufferedTransformation& bt, RandomNumberGenerator& rng, const DSA::PrivateKey& dsa,
              const std::string& algorithm, const char* password, size_t length);

void PEM_Save(BufferedTransformation& bt, const DL_PublicKey_EC<ECP>& ec);
void PEM_Save(BufferedTransformation& bt, const DL_PrivateKey_EC<ECP>& ec);
void PEM_Save(BufferedTransformation& bt, RandomNumberGenerator& rng, const DL_PrivateKey_EC<ECP>& ec,
              const std::string& algorithm, const char* password, size_t length);

void PEM_Save(BufferedTransformation& bt, const DL_PublicKey_EC<EC2N>& ec);
void PEM_Save(BufferedTransformation& bt, const DL_PrivateKey_EC<EC2N>& ec);
void PEM_Save(RandomNumberGenerator& rng,  BufferedTransformation& bt, const DL_PrivateKey_EC<EC2N>& ec,
              const std::string& algorithm, const char* password, size_t length);

void PEM_Save(BufferedTransformation& bt, const DL_Keys_ECDSA<ECP>::PrivateKey& ecdsa);
void PEM_Save(BufferedTransformation& bt, RandomNumberGenerator& rng, const DL_Keys_ECDSA<ECP>::PrivateKey& ecdsa,
              const std::string& algorithm, const char* password, size_t length);

void PEM_Save(BufferedTransformation& bt, const DL_GroupParameters_DSA& params);
void PEM_Save(BufferedTransformation& bt, const DL_GroupParameters_EC<ECP>& params);
void PEM_Save(BufferedTransformation& bt, const DL_GroupParameters_EC<EC2N>& params);

void PEM_DH_Save(BufferedTransformation& bt, const Integer& p, const Integer& g);
void PEM_DH_Save(BufferedTransformation& bt, const Integer& p, const Integer& q, const Integer& g);

NAMESPACE_END

#endif
