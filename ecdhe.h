//
// Created by Zed on 24/05/2024.
//

#ifndef DHE_ECDHE_H
#define DHE_ECDHE_H

#include "osrng.h"
#include "nbtheory.h"
#include "eccrypto.h"
#include "oids.h"
#include "integer.h"
#include "secblock.h"
#include "queue.h"
#include "asn.h"
#include "base64.h"
#include "files.h"
#include "filters.h"
#include "dh.h"

using namespace std;
using namespace CryptoPP;

void PrintHelp();

void PrintHelpForGenerate();

void PrintHelpForLoad();

string EncodePrivateKey(const SecByteBlock &privateKey);

string EncodePublicKey(const SecByteBlock &publicKey);

void
WritePrivateKeyAndPublicKey(const char *privateKeyFileName, const char *publicKeyFileName,
                            const SecByteBlock &privateKey,
                            const SecByteBlock &publicKey);

void GenerateAndSaveParameters(const char *fileToSave, int bitLength);

void LoadParametersAndGenerateKeys(const char *paramsInputFileName, const char *privateKeyFileName,
                                   const char *publicKeyFileName);

#endif //DHE_ECDHE_H
