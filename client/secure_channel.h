#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "crypto_engine.h"

// The encrypted connection to a relay (M8). Underneath both relay protocols (messaging and the older transfer-ID file
// transfer), so nothing crosses the network in the clear: not invites, not send tokens, not which mailbox signs in.
//
// Handshake (three messages, before anything else on the connection):
//   1. client → relay  ClientHello:  a one-connection X25519 public key and a random nonce
//   2. relay → client  ServerHello:  the relay's identity key (ML-DSA; its SHA-256 is the relay ID the app pins), a one-connection
//                                    ML-KEM-768 public key, a one-connection X25519 public key, a nonce, and the identity key's
//                                    signature over the whole exchange so far (so nothing in it can be swapped)
//   3. client → relay  ClientFinish: an ML-KEM encapsulation to the relay's one-connection key
// Both sides then hold three secrets' worth (ML-KEM, X25519) and derive one key for each direction with HKDF over everything
// exchanged. The one-connection keys are thrown away afterwards, so a recorded connection can't be opened later even with the
// relay's identity key. Frames are AES-256-GCM, each with the next number in its direction as the nonce: a frame replayed,
// reordered, dropped or altered fails, and the channel is then dead.
namespace securechannel {

using Bytes = std::vector<uint8_t>;

constexpr uint32_t VERSION = 1;
constexpr size_t NONCE_BYTES = 32;
constexpr size_t MAX_HANDSHAKE_BYTES = 16 * 1024;

struct ClientHello {
    Bytes x25519_public;  // 32
    Bytes nonce;          // NONCE_BYTES
};
struct ServerHello {
    Bytes identity_public;  // ML-DSA-65
    Bytes kem_public;       // ML-KEM-768, for this connection only
    Bytes x25519_public;    // for this connection only
    Bytes nonce;            // NONCE_BYTES
    Bytes signature;        // the identity key over the exchange so far
};
struct ClientFinish {
    Bytes kem_ciphertext;
};

// Strict encodings: a magic and version up front, every length checked, nothing extra allowed.
Bytes encode(const ClientHello&);
Bytes encode(const ServerHello&);
Bytes encode(const ClientFinish&);
std::optional<ClientHello> decode_client_hello(const Bytes&);
std::optional<ServerHello> decode_server_hello(const Bytes&);
std::optional<ClientFinish> decode_client_finish(const Bytes&);

struct Keys {
    Bytes send;  // 32
    Bytes recv;  // 32
};

// The client's side. `expected_relay_id` is the relay ID the app has pinned (empty: accept any, and report it so the caller
// can remember it: trust on first use).
class ClientHandshake {
public:
    ClientHandshake();
    ~ClientHandshake();
    Bytes hello();  // message 1
    // Message 2 in, message 3 out. False (with a reason) if the relay isn't the pinned one or anything doesn't check out.
    bool finish(const Bytes& server_hello, const Bytes& expected_relay_id, Bytes& client_finish, Keys& keys, Bytes& relay_id, std::string& error);

private:
    CryptoEngine::X25519KeyPair x25519_;
    Bytes hello_;
};

// The relay's side, with its identity key.
class ServerHandshake {
public:
    explicit ServerHandshake(const CryptoEngine::SigKeyPair& identity);
    ~ServerHandshake();
    // Message 1 in, message 2 out. False for a hello that isn't valid.
    bool reply(const Bytes& client_hello, Bytes& server_hello);
    // Message 3 in. False if it isn't valid.
    bool finish(const Bytes& client_finish, Keys& keys);

private:
    CryptoEngine::SigKeyPair identity_;
    CryptoEngine::KEMKeyPair kem_;
    CryptoEngine::X25519KeyPair x25519_;
    Bytes transcript_;   // client hello and server hello, as sent
    Bytes client_x25519_;
};

// Seals and opens frames once the handshake is done. Not thread-safe: one sender and one receiver at a time.
class Cipher {
public:
    explicit Cipher(const Keys& keys, bool is_client);
    ~Cipher();
    Bytes seal(const Bytes& plaintext);
    // Nothing if the frame isn't the next one in order, or was altered. After a failure every later frame fails too.
    std::optional<Bytes> open(const Bytes& sealed);

private:
    Bytes send_key_, recv_key_;
    uint64_t send_counter_ = 0, recv_counter_ = 0;
    bool is_client_;
    bool broken_ = false;
};

}  // namespace securechannel
