#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

constexpr int KEY_LEN = 32;
constexpr int NONCE_LEN = 12;
constexpr int TAG_LEN = 16;

using namespace std;

using Bytes = vector<unsigned char>;
using CtxPtr = unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static void check(int ok, const char *what) {
    if (ok != 1) throw runtime_error(what);
}

static void print_hex(const string &label, const Bytes &d) {
    cout << label << ": " << hex << setfill('0');
    for (unsigned char b : d) cout << setw(2) << static_cast<int>(b);
    cout << dec << "\n";
}

struct Sealed {
    Bytes ciphertext;
    Bytes tag;
};

static Sealed encrypt(const Bytes &key, const Bytes &nonce, const Bytes &aad,
                      const Bytes &plaintext) {
    CtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw runtime_error("ctx alloc");
    int len = 0;
    Sealed out{Bytes(plaintext.size()), Bytes(TAG_LEN)};

    check(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "init");
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr), "ivlen");
    check(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()), "key/nonce");
    check(EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())), "aad");
    check(EVP_EncryptUpdate(ctx.get(), out.ciphertext.data(), &len, plaintext.data(),
                            static_cast<int>(plaintext.size())), "encrypt");
    int total = len;
    check(EVP_EncryptFinal_ex(ctx.get(), out.ciphertext.data() + total, &len), "final");
    out.ciphertext.resize(total + len);
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, out.tag.data()), "get tag");
    return out;
}

static optional<Bytes> decrypt(const Bytes &key, const Bytes &nonce, const Bytes &aad,
                                    const Sealed &in) {
    CtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw runtime_error("ctx alloc");
    int len = 0;
    Bytes pt(in.ciphertext.size());

    check(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "init");
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr), "ivlen");
    check(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()), "key/nonce");
    check(EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())), "aad");
    check(EVP_DecryptUpdate(ctx.get(), pt.data(), &len, in.ciphertext.data(),
                            static_cast<int>(in.ciphertext.size())), "decrypt");
    int total = len;
    check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                              const_cast<unsigned char *>(in.tag.data())), "set tag");
    if (EVP_DecryptFinal_ex(ctx.get(), pt.data() + total, &len) != 1)
        return nullopt;
    pt.resize(total + len);
    return pt;
}

int main() {
    try {
        const string msg = "Test message for AES-256-GCM";
        const string header = "lab1-header";
        const Bytes plaintext(msg.begin(), msg.end());
        const Bytes aad(header.begin(), header.end());

        Bytes key(KEY_LEN);
        check(RAND_bytes(key.data(), KEY_LEN), "RAND_bytes key");
        print_hex("key  ", key);

        Bytes nonce(NONCE_LEN);
        check(RAND_bytes(nonce.data(), NONCE_LEN), "RAND_bytes nonce");
        print_hex("nonce", nonce);
        Sealed sealed = encrypt(key, nonce, aad, plaintext);
        print_hex("ct   ", sealed.ciphertext);
        print_hex("tag  ", sealed.tag);

        auto ok = decrypt(key, nonce, aad, sealed);
        if (!ok) throw runtime_error("unexpected auth failure");
        cout << "decrypted: \"" << string(ok->begin(), ok->end()) << "\" -> OK\n";

        sealed.ciphertext[0] ^= 0x01;
        auto bad = decrypt(key, nonce, aad, sealed);
        cout << "tampered ciphertext: "
            << (bad ? "accepted (UNEXPECTED)" : "decryption REJECTED (tag mismatch)") << "\n";
    } catch (const exception &e) {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
