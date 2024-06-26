#include "dhe.h"

void PrintHelp() {
    cout << "Usage: \n"
         << "  generate <file>   Generate DHE parameters and save to file\n"
         << "  load <file>       Load DHE parameters from file and generate keys\n"
         << "  help              Show this help message\n";
}

void PrintHelpForGenerate() {
    cout << "Usage: \n"
         << "  generate <file> <bitLength>   Generate DHE parameters and save to file\n";
}

void PrintHelpForLoad() {
    cout << "Usage: \n"
         << "  load <file> <privateOutputFile> <publicOutputFile>   Load DHE parameters from file and generate keys\n";
}

string EncodePrivateKey(const SecByteBlock &privateKey) {
    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    encoder.Put(privateKey, privateKey.size());
    encoder.MessageEnd();
    return "-----BEGIN PRIVATE KEY-----\n" + encoded + "-----END PRIVATE KEY-----";
}

string EncodePublicKey(const SecByteBlock &publicKey) {
    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    encoder.Put(publicKey, publicKey.size());
    encoder.MessageEnd();
    return "-----BEGIN PUBLIC KEY-----\n" + encoded + "-----END PUBLIC KEY-----";
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

void GenerateAndSaveParameters(const char *fileToSave, int bitLength) {
    AutoSeededRandomPool rng;

    Integer p, q, g;
    bool isValidPrime = false;

    while (!isValidPrime) {
        PrimeAndGenerator pg(1, rng, bitLength, bitLength - 1);
        p = pg.Prime();
        q = pg.SubPrime();
        g = pg.Generator();

        isValidPrime = RabinMillerTest(rng, p, 10) && RabinMillerTest(rng, q, 10) && RabinMillerTest(rng, g, 10);
    }

    ByteQueue queue;
    DERSequenceEncoder derSeq(queue);
    p.DEREncode(derSeq);
    q.DEREncode(derSeq);
    g.DEREncode(derSeq);
    derSeq.MessageEnd();

    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);
    queue.CopyTo(encoder);
    encoder.MessageEnd();

    ofstream file(fileToSave);
    file << "-----BEGIN DH PARAMETERS-----\n";
    file << encoded;
    file << "-----END DH PARAMETERS-----\n";

    file.close();
    cout << "Parameters saved to " << fileToSave << endl;
}

void
LoadParametersAndGenerateKeys(const char *paramsInputFileName, const char *privateKeyFileName,
                              const char *publicKeyFileName) {
    AutoSeededRandomPool rng;

    ifstream file(paramsInputFileName);
    string pem((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());

    size_t begin = pem.find("-----BEGIN DH PARAMETERS-----");
    size_t end = pem.find("-----END DH PARAMETERS-----");

    if (begin == string::npos || end == string::npos) {
        throw runtime_error("Invalid PEM format");
    }

    begin += 30;
    end -= 1;

    string base64 = pem.substr(begin, end - begin);

    ByteQueue queue;
    StringSource stringSource(base64, true, new Base64Decoder(new Redirector(queue)));

    Integer p, q, g;
    BERSequenceDecoder seq(queue);
    p.BERDecode(seq);
    q.BERDecode(seq);
    g.BERDecode(seq);

    seq.MessageEnd();

    DH dh;
    dh.AccessGroupParameters().Initialize(p, q, g);

    size_t privateKeyLength = (q.BitCount() + 7) / 8;

    Integer privateInt;
    privateInt.Randomize(rng, Integer::One(), q - Integer::One());

    SecByteBlock privateKey(privateKeyLength);
    privateInt.Encode(privateKey.BytePtr(), privateKey.SizeInBytes());

    SecByteBlock publicKey(dh.PublicKeyLength());
    dh.GeneratePublicKey(rng, privateKey, publicKey);

    WritePrivateKeyAndPublicKey(privateKeyFileName, publicKeyFileName, privateKey, publicKey);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 0;
    }

    string mode = argv[1];

    if (mode == "generate") {
        if (argc < 4) {
            PrintHelpForGenerate();
            return 0;
        }

        const char *filename = argv[2];
        int bitLength = stoi(argv[3]);

        GenerateAndSaveParameters(filename, bitLength);
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