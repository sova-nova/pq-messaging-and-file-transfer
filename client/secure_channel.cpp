#include "secure_channel.h"

#include <mutex>
#include <stdexcept>

#include "protocol.h"

namespace securechannel {

namespace {

const char MAGIC[] = "PQSC";
const char TRANSCRIPT_LABEL[] = "pq-suite relay channel v1";
const char C2S[] = "pq-suite relay channel client to relay";
const char S2C[] = "pq-suite relay channel relay to client";

void write_header(Bytes& b, uint32_t kind) {
    b.insert(b.end(), MAGIC, MAGIC + 4);
    write_u32(b, VERSION);
    write_u32(b, kind);
}

bool read_header(const Bytes& in, size_t& off, uint32_t kind) {
    if (in.size() < 12 || std::string(in.begin(), in.begin() + 4) != MAGIC) return false;
    off = 4;
    auto version = read_u32(in.data(), in.size(), off);
    auto k = read_u32(in.data(), in.size(), off);
    return version && *version == VERSION && k && *k == kind;
}

std::optional<Bytes> exact_blob(const Bytes& in, size_t& off, size_t size) {
    auto b = read_blob(in.data(), in.size(), off, size);
    if (!b || b->size() != size) return std::nullopt;
    return b;
}

Bytes signed_part(const Bytes& client_hello, const ServerHello& s) {
    Bytes t;
    write_string(t, TRANSCRIPT_LABEL);
    write_blob(t, client_hello);
    write_blob(t, s.identity_public);
    write_blob(t, s.kem_public);
    write_blob(t, s.x25519_public);
    write_blob(t, s.nonce);
    return t;
}

Keys derive(const Bytes& kem_secret, const Bytes& x25519_secret, const Bytes& transcript, bool for_client) {
    Bytes ikm = kem_secret;
    ikm.insert(ikm.end(), x25519_secret.begin(), x25519_secret.end());
    const Bytes salt = CryptoEngine::sha256(transcript);
    Bytes c2s = CryptoEngine::hkdf_sha256(ikm, salt, C2S, 32);
    Bytes s2c = CryptoEngine::hkdf_sha256(ikm, salt, S2C, 32);
    CryptoEngine::secure_wipe(ikm);
    return for_client ? Keys{c2s, s2c} : Keys{s2c, c2s};
}

Bytes nonce_for(uint64_t counter) {
    Bytes n(12, 0);
    for (int i = 0; i < 8; i++) n[11 - i] = static_cast<uint8_t>(counter >> (8 * i));
    return n;
}

}  // namespace

Bytes encode(const ClientHello& m) {
    if (m.x25519_public.size() != 32 || m.nonce.size() != NONCE_BYTES) throw std::runtime_error("That hello is not valid");
    Bytes b;
    write_header(b, 1);
    write_blob(b, m.x25519_public);
    write_blob(b, m.nonce);
    return b;
}

Bytes encode(const ServerHello& m) {
    Bytes b;
    write_header(b, 2);
    write_blob(b, m.identity_public);
    write_blob(b, m.kem_public);
    write_blob(b, m.x25519_public);
    write_blob(b, m.nonce);
    write_blob(b, m.signature);
    return b;
}

Bytes encode(const ClientFinish& m) {
    Bytes b;
    write_header(b, 3);
    write_blob(b, m.kem_ciphertext);
    return b;
}

std::optional<ClientHello> decode_client_hello(const Bytes& in) {
    size_t off = 0;
    if (in.size() > MAX_HANDSHAKE_BYTES || !read_header(in, off, 1)) return std::nullopt;
    auto x = exact_blob(in, off, 32);
    auto nonce = exact_blob(in, off, NONCE_BYTES);
    if (!x || !nonce || off != in.size()) return std::nullopt;
    return ClientHello{std::move(*x), std::move(*nonce)};
}

std::optional<ServerHello> decode_server_hello(const Bytes& in) {
    size_t off = 0;
    if (in.size() > MAX_HANDSHAKE_BYTES || !read_header(in, off, 2)) return std::nullopt;
    auto identity = exact_blob(in, off, CryptoEngine::sig_public_key_size());
    auto kem = exact_blob(in, off, CryptoEngine::kem_public_key_size());
    auto x = exact_blob(in, off, 32);
    auto nonce = exact_blob(in, off, NONCE_BYTES);
    auto sig = read_blob(in.data(), in.size(), off, 8192);
    if (!identity || !kem || !x || !nonce || !sig || sig->empty() || off != in.size()) return std::nullopt;
    return ServerHello{std::move(*identity), std::move(*kem), std::move(*x), std::move(*nonce), std::move(*sig)};
}

std::optional<ClientFinish> decode_client_finish(const Bytes& in) {
    size_t off = 0;
    if (in.size() > MAX_HANDSHAKE_BYTES || !read_header(in, off, 3)) return std::nullopt;
    auto ct = exact_blob(in, off, CryptoEngine::kem_ciphertext_size());
    if (!ct || off != in.size()) return std::nullopt;
    return ClientFinish{std::move(*ct)};
}

ClientHandshake::ClientHandshake() : x25519_(CryptoEngine::generate_x25519()) {}
ClientHandshake::~ClientHandshake() { CryptoEngine::secure_wipe(x25519_.private_key); }

Bytes ClientHandshake::hello() {
    hello_ = encode(ClientHello{x25519_.public_key, CryptoEngine::random_bytes(NONCE_BYTES)});
    return hello_;
}

bool ClientHandshake::finish(const Bytes& server_hello, const Bytes& expected_relay_id, Bytes& client_finish, Keys& keys, Bytes& relay_id, std::string& error) {
    auto s = decode_server_hello(server_hello);
    if (hello_.empty() || !s) {
        error = "The relay's answer isn't valid";
        return false;
    }
    relay_id = CryptoEngine::sha256(s->identity_public);
    if (!expected_relay_id.empty() && relay_id != expected_relay_id) {
        error = "This isn't the relay you trusted: its identity has changed. Check with the relay's operator.";
        return false;
    }
    bool signed_ok = false;
    try {
        signed_ok = CryptoEngine::verify(signed_part(hello_, *s), s->signature, s->identity_public);
    } catch (const std::exception&) {
        signed_ok = false;
    }
    if (!signed_ok) {
        error = "The relay's answer isn't signed by its key";
        return false;
    }
    try {
        auto encap = CryptoEngine::encapsulate(s->kem_public);
        Bytes x = CryptoEngine::x25519_shared(x25519_.private_key, s->x25519_public);
        client_finish = encode(ClientFinish{encap.ciphertext});
        Bytes transcript = signed_part(hello_, *s);
        write_blob(transcript, s->signature);
        write_blob(transcript, client_finish);
        keys = derive(encap.shared_secret, x, transcript, true);
        CryptoEngine::secure_wipe(encap.shared_secret);
        CryptoEngine::secure_wipe(x);
    } catch (const std::exception& e) {
        error = std::string("The connection could not be secured: ") + e.what();
        return false;
    }
    CryptoEngine::secure_wipe(x25519_.private_key);  // used once
    return true;
}

ServerHandshake::ServerHandshake(const CryptoEngine::SigKeyPair& identity)
    : identity_(identity), kem_(CryptoEngine::generate_kem_keypair()), x25519_(CryptoEngine::generate_x25519()) {}

ServerHandshake::~ServerHandshake() {
    CryptoEngine::secure_wipe(kem_.private_key);
    CryptoEngine::secure_wipe(x25519_.private_key);
}

bool ServerHandshake::reply(const Bytes& client_hello, Bytes& server_hello) {
    auto c = decode_client_hello(client_hello);
    if (!c) return false;
    client_x25519_ = c->x25519_public;
    ServerHello s;
    s.identity_public = identity_.public_key;
    s.kem_public = kem_.public_key;
    s.x25519_public = x25519_.public_key;
    s.nonce = CryptoEngine::random_bytes(NONCE_BYTES);
    s.signature = CryptoEngine::sign(signed_part(client_hello, s), identity_.private_key);
    server_hello = encode(s);
    transcript_ = signed_part(client_hello, s);
    write_blob(transcript_, s.signature);
    return true;
}

bool ServerHandshake::finish(const Bytes& client_finish, Keys& keys) {
    auto f = decode_client_finish(client_finish);
    if (!f || transcript_.empty()) return false;
    try {
        Bytes kem_secret = CryptoEngine::decapsulate(f->kem_ciphertext, kem_.private_key);
        Bytes x = CryptoEngine::x25519_shared(x25519_.private_key, client_x25519_);
        Bytes transcript = transcript_;
        write_blob(transcript, client_finish);
        keys = derive(kem_secret, x, transcript, false);
        CryptoEngine::secure_wipe(kem_secret);
        CryptoEngine::secure_wipe(x);
    } catch (const std::exception&) {
        return false;
    }
    CryptoEngine::secure_wipe(kem_.private_key);  // used once
    CryptoEngine::secure_wipe(x25519_.private_key);
    return true;
}

Cipher::Cipher(const Keys& keys, bool is_client) : send_key_(keys.send), recv_key_(keys.recv), is_client_(is_client) {
    if (send_key_.size() != 32 || recv_key_.size() != 32) throw std::runtime_error("The channel keys are not valid");
}

Cipher::~Cipher() {
    CryptoEngine::secure_wipe(send_key_);
    CryptoEngine::secure_wipe(recv_key_);
}

Bytes Cipher::seal(const Bytes& plaintext) {
    if (send_counter_ == UINT64_MAX) throw std::runtime_error("The channel has been used up");
    const Bytes aad(is_client_ ? C2S : S2C, (is_client_ ? C2S : S2C) + std::char_traits<char>::length(is_client_ ? C2S : S2C));
    return CryptoEngine::encrypt(send_key_, nonce_for(send_counter_++), plaintext, aad);
}

std::optional<Bytes> Cipher::open(const Bytes& sealed) {
    if (broken_) return std::nullopt;
    const char* label = is_client_ ? S2C : C2S;
    const Bytes aad(label, label + std::char_traits<char>::length(label));
    try {
        auto plain = CryptoEngine::decrypt(recv_key_, nonce_for(recv_counter_), sealed, aad);
        recv_counter_++;
        return plain;
    } catch (const std::exception&) {
        broken_ = true;  // one bad frame and the channel is finished
        return std::nullopt;
    }
}

namespace {
class SocketCipher : public FrameCipher {
public:
    SocketCipher(const Keys& keys, bool is_client) : cipher_(keys, is_client) {}
    std::vector<uint8_t> seal(const std::vector<uint8_t>& frame) override {
        std::lock_guard<std::mutex> lock(send_mutex_);
        return cipher_.seal(frame);
    }
    std::optional<std::vector<uint8_t>> open(const std::vector<uint8_t>& sealed) override {
        std::lock_guard<std::mutex> lock(recv_mutex_);
        return cipher_.open(sealed);
    }

private:
    Cipher cipher_;
    std::mutex send_mutex_, recv_mutex_;  // sending and receiving may happen on different threads; each direction has its own counter
};
}  // namespace

bool secure_client(socket_t sock, const Bytes& expected_relay_id, Bytes& relay_id, std::string& error) {
    ClientHandshake hs;
    Bytes finish;
    Keys keys;
    if (!send_handshake(sock, hs.hello())) {
        error = "Could not reach the relay";
        return false;
    }
    auto reply = recv_handshake(sock);
    if (!reply) {
        error = "The relay didn't answer the encrypted handshake (is it an older relay that needs updating?)";
        return false;
    }
    if (!hs.finish(*reply, expected_relay_id, finish, keys, relay_id, error)) return false;
    if (!send_handshake(sock, finish)) {
        error = "Could not reach the relay";
        return false;
    }
    attach_frame_cipher(sock, std::make_shared<SocketCipher>(keys, true));
    return true;
}

bool secure_server(socket_t sock, const CryptoEngine::SigKeyPair& identity) {
    ServerHandshake hs(identity);
    Bytes reply;
    Keys keys;
    auto hello = recv_handshake(sock);
    if (!hello || !hs.reply(*hello, reply) || !send_handshake(sock, reply)) return false;
    auto finish = recv_handshake(sock);
    if (!finish || !hs.finish(*finish, keys)) return false;
    attach_frame_cipher(sock, std::make_shared<SocketCipher>(keys, false));
    return true;
}

}  // namespace securechannel
