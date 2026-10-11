#include <openssl/evp.h>

#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

using Bytes = vector<unsigned char>;
using PkeyPtr = unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using MdCtxPtr = unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

static void check(int ok, const char *what) {
    if (ok != 1) throw runtime_error(what);
}

static PkeyPtr generate_key() {
    PkeyCtxPtr kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    if (!kctx) throw runtime_error("ctx alloc");
    check(EVP_PKEY_keygen_init(kctx.get()), "keygen_init");
    EVP_PKEY *raw = nullptr;
    check(EVP_PKEY_keygen(kctx.get(), &raw), "keygen");
    return PkeyPtr(raw, EVP_PKEY_free);
}

static Bytes sign(const PkeyPtr &priv, const string &msg) {
    MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw runtime_error("ctx alloc");
    check(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, priv.get()), "sign_init");
    size_t siglen = 0;
    auto *m = reinterpret_cast<const unsigned char *>(msg.data());
    check(EVP_DigestSign(ctx.get(), nullptr, &siglen, m, msg.size()), "sign_len");
    Bytes sig(siglen);
    check(EVP_DigestSign(ctx.get(), sig.data(), &siglen, m, msg.size()), "sign");
    sig.resize(siglen);
    return sig;
}

static bool verify(const PkeyPtr &pub, const string &msg, const Bytes &sig) {
    MdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw runtime_error("ctx alloc");
    check(EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pub.get()), "verify_init");
    auto *m = reinterpret_cast<const unsigned char *>(msg.data());
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), m, msg.size()) == 1;
}

int main() {
    try {
        PkeyPtr key = generate_key();

        string msg = "Document to be signed";
        Bytes sig = sign(key, msg);
        cout << "signature (" << sig.size() << " bytes): " << hex << setfill('0');
        for (unsigned char b : sig) cout << setw(2) << static_cast<int>(b);
        cout << dec << "\n";

        cout << "verify original : " << (verify(key, msg, sig) ? "VALID" : "INVALID") << "\n";

        msg[0] ^= 0x01;
        cout << "verify modified : "
                  << (verify(key, msg, sig) ? "VALID (UNEXPECTED)" : "INVALID") << "\n";
    } catch (const exception &e) {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
