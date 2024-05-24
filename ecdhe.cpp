//
// Created by Zed on 24/05/2024.
//

#include "ecdhe.h"

void PrintHelp() {
    cout << "Usage: \n"
         << "  generate <file>   Generate ECDHE parameters and save to file\n"
         << "  load <file>       Load ECDHE parameters from file and generate keys\n"
         << "  help              Show this help message\n";
}

void PrintHelpForGenerate() {
    cout << "Usage: \n"
         << "  generate <file>   Generate ECDHE parameters and save to file\n";
}

void PrintHelpForLoad() {
    cout << "Usage: \n"
         << "  load <file> <privateOutputFile> <publicOutputFile>   Load ECDHE parameters from file and generate keys\n";
}

string EncodePrivateKey(const SecByteBlock &privateKey) {
    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    encoder.Put(privateKey, privateKey.size());
    encoder.MessageEnd();
    return "-----BEGIN EC PRIVATE KEY-----\n" + encoded + "-----END EC PRIVATE KEY-----";
}

string EncodePublicKey(const SecByteBlock &pubKey) {
    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    encoder.Put(pubKey, pubKey.size());
    encoder.MessageEnd();
    return "-----BEGIN EC PUBLIC KEY-----\n" + encoded + "-----END EC PUBLIC KEY-----";
}

void
WritePrivateKeyAndPublicKey(const char *privateKeyFileName, const char *publicKeyFileName,
                            const SecByteBlock &privateKey,
                            const SecByteBlock &publicKey) {
    string privateKeyEncoded = EncodePrivateKey(privateKey);
    ofstream privateFile(privateKeyFileName);
    privateFile << privateKeyEncoded;
    privateFile.close();

    string publicKeyEncoded = EncodePublicKey(publicKey);
    ofstream publicFile(publicKeyFileName);
    publicFile << publicKeyEncoded;
    publicFile.close();
}

void GenerateAndSaveParameters(const char *fileToSave) {
    AutoSeededRandomPool rng;

    OID curve = ASN1::secp256r1();

    ByteQueue queue;
    curve.DEREncode(queue);

    std::string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    queue.CopyTo(encoder);
    encoder.MessageEnd();

    ofstream file(fileToSave);
    file << "-----BEGIN EC PARAMETERS-----\n";
    file << encoded;
    file << "-----END EC PARAMETERS-----\n";

    file.close();
    cout << "Parameters saved to " << fileToSave << endl;
}

void
LoadParametersAndGenerateKeys(const char *paramsInputFileName, const char *privateKeyFileName,
                              const char *publicKeyFileName) {
    AutoSeededRandomPool rng;

    ifstream file(paramsInputFileName);
    string pem((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

    size_t begin = pem.find("-----BEGIN EC PARAMETERS-----");
    size_t end = pem.find("-----END EC PARAMETERS-----");

    if (begin == string::npos || end == string::npos) {
        throw runtime_error("Invalid PEM format");
    }

    begin += 27;
    end -= 1;

    string base64 = pem.substr(begin, end - begin);

    ByteQueue queue;
    StringSource stringSource(base64, true, new Base64Decoder(new Redirector(queue)));

    OID curve;
    curve.BERDecode(queue);

    ECDH<ECP>::Domain dh(curve);

    SecByteBlock privateKey(dh.PrivateKeyLength());
    SecByteBlock publicKey(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, privateKey, publicKey);

    WritePrivateKeyAndPublicKey(privateKeyFileName, publicKeyFileName, privateKey, publicKey);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 0;
    }

    string mode = argv[1];

    if (mode == "generate") {
        if (argc < 3) {
            PrintHelpForGenerate();
            return 0;
        }

        const char *filename = argv[2];

        GenerateAndSaveParameters(filename);
    } else if (mode == "load") {
        if (argc < 5) {
            PrintHelpForLoad();
            return 0;
        }

        const char *filename = argv[2];

        cout << "Loading parameters from " << filename << endl;

        const char *privateKeyFileName = argv[3];
        const char *publicKeyFileName = argv[4];

        LoadParametersAndGenerateKeys(filename, privateKeyFileName, publicKeyFileName);
    } else {
        PrintHelp();

        return 0;
    }
}