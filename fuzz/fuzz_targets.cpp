#include "fuzz_targets.h"

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>

#include "archive.h"
#include "crypto_engine.h"
#include "envelope.h"
#include "identity_bundle.h"
#include "keyring.h"
#include "message_record.h"
#include "prekey.h"
#include "protocol.h"
#include "relay_protocol.h"
#include "secure_channel.h"
#include "sharing.h"

namespace fuzz {

namespace {

[[noreturn]] void violated(const char* what) {
    std::fprintf(stderr, "FUZZ FAILURE: %s\n", what);
    std::abort();
}

Bytes R(size_t n, uint8_t seed = 1) {
    Bytes b(n);
    for (size_t i = 0; i < n; i++) b[i] = static_cast<uint8_t>(seed * 31 + i * 7);
    return b;
}

Bytes prefixed(uint8_t selector, const Bytes& body) {
    Bytes b{selector};
    b.insert(b.end(), body.begin(), body.end());
    return b;
}

// Keys made once and reused, so seeds can be real (signed, sealed) and the parsers that need a key can be given one.
struct Fixed {
    CryptoEngine::SigKeyPair sig = CryptoEngine::generate_sig_keypair();
    CryptoEngine::KEMKeyPair kem = CryptoEngine::generate_kem_keypair();
    prekey::Generated pre = prekey::generate(sig.private_key, false, 1700000000);
    Bytes key32 = R(32, 9);
    Bytes id16 = R(16, 5);
};
Fixed& fixed() {
    static Fixed f;
    return f;
}

// --- The relay protocol: every decoder, and each must round trip ---

template <typename T>
bool roundtrip(const Bytes& in, std::optional<T> (*decode)(const std::vector<uint8_t>&), const char* name) {
    auto v = decode(in);
    if (!v) return false;
    if (relay::encode(*v) != in) violated(name);
    return true;
}

using RelayDecoder = std::function<bool(const Bytes&)>;
const std::vector<RelayDecoder>& relay_decoders() {
    static const std::vector<RelayDecoder> d = {
        [](const Bytes& b) { return roundtrip(b, relay::decode_hello, "hello"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_hello_reply, "hello reply"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_register, "register"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_auth, "auth"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_deposit, "deposit"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_stored_envelope, "stored envelope"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_id_list, "id list"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_hash_op, "hash op"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_invite_status, "invite status"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_create, "archive create"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_join, "archive join"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_auth, "archive auth"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_append, "archive append"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_head, "archive head"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_fetch, "archive fetch"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_entry, "archive entry"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_keyring_chunk, "keyring chunk"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_archive_delete, "archive delete"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_revoke, "revoke"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_prekey_put, "prekey put"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_prekey_take, "prekey take"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_prekey_data, "prekey data"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_prekey_status, "prekey status"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_file_begin, "file begin"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_file_chunk, "file chunk"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_file_download, "file download"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_file_info, "file info"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_file_redeem, "file redeem"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_file_ref, "file ref"); },
        [](const Bytes& b) { return roundtrip(b, relay::decode_file_status, "file status"); },
    };
    return d;
}

bool run_relay(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    const auto& d = relay_decoders();
    return d[data[0] % d.size()](Bytes(data + 1, data + size));
}

std::vector<Bytes> seeds_relay() {
    auto& f = fixed();
    const Bytes sig = CryptoEngine::sign(Bytes{1}, f.sig.private_key);
    using namespace relay;
    std::vector<Bytes> s;
    auto add = [&](uint8_t i, const Bytes& b) { s.push_back(prefixed(i, b)); };
    add(0, encode(Hello{3, R(NONCE_BYTES)}));
    add(1, encode(HelloReply{f.sig.public_key, sig, R(NONCE_BYTES)}));
    add(2, encode(Register{R(INVITE_BYTES), R(MAILBOX_ID_BYTES), f.sig.public_key, R(32), sig}));
    add(3, encode(Auth{R(MAILBOX_ID_BYTES), sig}));
    add(4, encode(Deposit{R(MAILBOX_ID_BYTES), R(SEND_TOKEN_BYTES), R(300), 3600, R(32)}));
    add(5, encode(StoredEnvelope{R(ENVELOPE_ID_BYTES), 1700000000, R(32), R(300)}));
    add(6, encode(IdList{{R(ENVELOPE_ID_BYTES), R(ENVELOPE_ID_BYTES, 2)}}));
    add(7, encode(HashOp{R(32)}));
    {
        InviteStatus st;
        st.max_unused = 3;
        st.max_total = 10;
        st.unused = {InviteStatus::Unused{R(32), 1700000000}};
        st.joined = {InviteStatus::Joined{R(MAILBOX_ID_BYTES), 1700000001}};
        add(8, encode(st));
    }
    add(9, encode(ArchiveCreate{R(ARCHIVE_ID_BYTES), {R(32), R(32, 3)}}));
    add(10, encode(ArchiveJoin{R(ARCHIVE_ID_BYTES), R(JOIN_TOKEN_BYTES), f.sig.public_key, sig}));
    add(11, encode(ArchiveAuth{R(ARCHIVE_ID_BYTES), R(32), sig}));
    add(12, encode(ArchiveAppend{4, R(32), R(500)}));
    add(13, encode(ArchiveHead{4, R(32)}));
    add(14, encode(ArchiveFetch{1, 50}));
    add(15, encode(ArchiveEntry{4, R(32), R(500), false}));
    add(16, encode(KeyringChunk{1000, 0, 1, R(1000)}));
    {
        ArchiveDelete del;
        del.scope = DELETE_SCOPE_ENTRIES;
        del.op_id = R(16);
        del.expires_at = 1700000000;
        del.entry_hashes = {R(32)};
        del.signatures = {ArchiveSignature{R(32), sig}};
        add(17, encode(del));
    }
    add(18, encode(Revoke{R(MAILBOX_ID_BYTES), R(ENVELOPE_ID_BYTES), R(32)}));
    {
        PrekeyPut put;
        put.replace = true;
        put.generation = R(PREKEY_GENERATION_BYTES);
        put.prekeys = {PrekeyEntry{R(PREKEY_ID_BYTES), false, prekey::encode(f.pre.prekey)}};
        add(19, encode(put));
    }
    add(20, encode(PrekeyTake{R(MAILBOX_ID_BYTES), R(SEND_TOKEN_BYTES)}));
    add(21, encode(PrekeyData{false, prekey::encode(f.pre.prekey)}));
    add(22, encode(PrekeyStatus{57, true, R(PREKEY_GENERATION_BYTES)}));
    {
        FileBegin fb;
        fb.file_id = R(FILE_ID_BYTES);
        fb.total_size = 10 * 4096 + 100;
        fb.chunk_size = 4096;
        fb.chunk_count = 11;
        fb.expires_at = 1700000000;
        fb.token_hashes = {R(32), R(32, 4)};
        add(23, encode(fb));
    }
    add(24, encode(relay::FileChunk{3, R(4096)}));
    add(25, encode(FileDownload{R(FILE_ID_BYTES), R(FILE_TOKEN_BYTES), 2}));
    add(26, encode(FileInfo{10 * 4096 + 100, 4096, 11, 1700000000}));
    add(27, encode(FileRedeem{R(FILE_ID_BYTES), R(FILE_TOKEN_BYTES)}));
    add(28, encode(FileRef{R(FILE_ID_BYTES)}));
    add(29, encode(FileStatus{3, 1, 1700000000, true}));
    return s;
}

// --- Records and their payloads ---

Bytes signed_record(chat::RecordType type, const Bytes& payload) {
    auto& f = fixed();
    chat::Record r;
    r.conversation_id = R(chat::ID_BYTES);
    r.message_id = R(chat::ID_BYTES, 2);
    r.sender = CryptoEngine::sha256(f.sig.public_key);
    r.recipients_hash = R(chat::HASH_BYTES);
    r.sent_at = 1700000000;
    r.type = type;
    r.payload = payload;
    return chat::sign_record(r, f.sig.private_key);
}

chat::AttachmentInfo sample_attachment() {
    chat::AttachmentInfo a;
    a.file_id = R(16);
    a.name = "photo.jpg";
    a.size = 123456;
    a.sha256 = R(32);
    a.expires_at = 1700000000;
    a.relay_address = "10.0.0.1:9000";
    a.relay_id = R(32);
    a.caption = "hello";
    return a;
}

bool run_records(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    const Bytes in(data + 1, data + size);
    switch (data[0] % 8) {
        case 0: {  // a whole record, and whatever its payload says it is
            auto sr = chat::parse_record(in);
            if (!sr) return false;
            if (sr->raw != in) violated("record raw");
            const Bytes& p = sr->record.payload;
            chat::parse_attachment_payload(p);
            chat::parse_receipt_payload(p);
            chat::parse_private_start_payload(p);
            chat::parse_retract_payload(p);
            chat::parse_checkpoint_payload(p);
            chat::parse_delete_request_payload(p);
            chat::parse_delete_accept_payload(p);
            chat::parse_conversation_payload(p);
            chat::parse_forward_payload(p);
            chat::parse_archive_grant_payload(p);
            return true;
        }
        case 1: {
            auto a = chat::parse_attachment_payload(in);
            if (a && chat::attachment_payload(*a) != in) violated("attachment payload");
            return a.has_value();
        }
        case 2: {
            auto r = chat::parse_private_start_payload(in);
            if (r && chat::private_start_payload(*r) != in) violated("private start payload");
            return r.has_value();
        }
        case 3: {
            auto r = chat::parse_retract_payload(in);
            if (r && chat::retract_payload(*r) != in) violated("retract payload");
            return r.has_value();
        }
        case 4: return chat::parse_receipt_payload(in).has_value();
        case 5: return chat::parse_checkpoint_payload(in).has_value();
        case 6: return chat::parse_delete_request_payload(in).has_value() || chat::parse_delete_accept_payload(in).has_value();
        default: return chat::parse_conversation_payload(in).has_value() || chat::parse_forward_payload(in).has_value() || chat::parse_archive_grant_payload(in).has_value();
    }
}

std::vector<Bytes> seeds_records() {
    std::vector<Bytes> s;
    s.push_back(prefixed(0, signed_record(chat::RecordType::Text, Bytes{'h', 'i'})));
    s.push_back(prefixed(0, signed_record(chat::RecordType::Attachment, chat::attachment_payload(sample_attachment()))));
    s.push_back(prefixed(0, signed_record(chat::RecordType::Receipt, chat::receipt_payload(chat::ReceiptKind::Read, {R(16)}))));
    s.push_back(prefixed(0, signed_record(chat::RecordType::PrivateStart, chat::private_start_payload({chat::PrivateMode::FromReading, 86400}))));
    s.push_back(prefixed(0, signed_record(chat::RecordType::Retract, chat::retract_payload(R(16)))));
    s.push_back(prefixed(1, chat::attachment_payload(sample_attachment())));
    s.push_back(prefixed(2, chat::private_start_payload({chat::PrivateMode::FromSending, 3600})));
    s.push_back(prefixed(3, chat::retract_payload(R(16))));
    s.push_back(prefixed(4, chat::receipt_payload(chat::ReceiptKind::Delivered, {R(16), R(16, 3)})));
    s.push_back(prefixed(5, chat::checkpoint_payload(7, R(32))));
    return s;
}

// --- Envelopes (sealed to a key the fuzzer holds, so the inside is reached too) ---

bool run_envelope(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    auto& f = fixed();
    const Bytes in(data + 1, data + size);
    if (data[0] % 2 == 0) return chat::decode_inner(in).has_value();
    chat::envelope_prekey_id(in);
    auto opened = chat::open_envelope(in, f.kem.private_key, [&](const Bytes& id) -> std::optional<prekey::Secret> {
        if (id == f.pre.prekey.id) return f.pre.secret;
        return std::nullopt;
    });
    return opened.has_value();
}

std::vector<Bytes> seeds_envelope() {
    auto& f = fixed();
    chat::Inner in;
    in.records = {signed_record(chat::RecordType::Text, Bytes{'h', 'i'})};
    in.grants = {{R(16), R(32), R(32)}};
    chat::Inner plain;
    plain.records = in.records;
    return {prefixed(0, chat::encode_inner(in)), prefixed(0, chat::encode_inner(plain)), prefixed(1, chat::seal_envelope(plain, f.kem.public_key)),
            prefixed(1, chat::seal_envelope(in, f.kem.public_key, &f.pre.prekey))};
}

// --- Prekeys ---

bool run_prekey(const uint8_t* data, size_t size) {
    const Bytes in(data, data + size);
    auto p = prekey::decode(in);
    if (p && prekey::encode(*p) != in) violated("prekey");
    auto sec = prekey::decode_secret(in);
    if (sec && prekey::encode_secret(*sec) != in) violated("prekey secret");
    return p.has_value() || sec.has_value();
}

std::vector<Bytes> seeds_prekey() {
    auto& f = fixed();
    return {prekey::encode(f.pre.prekey), prekey::encode_secret(f.pre.secret)};
}

// --- Keyrings and archive entries ---

bool run_keyring(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    auto& f = fixed();
    const Bytes in(data + 1, data + size);
    if (data[0] % 2 == 0) {
        auto c = keyring::parse(in);
        if (c && keyring::serialize(*c) != in) violated("keyring");
        return c.has_value();
    }
    auto plain = keyring::open(f.key32, f.id16, in);
    if (plain) keyring::parse(*plain);
    return plain.has_value();
}

std::vector<Bytes> seeds_keyring() {
    auto& f = fixed();
    keyring::Contents c;
    c.verified = {std::string(64, 'a')};
    const Bytes plain = keyring::serialize(c);
    return {prefixed(0, plain), prefixed(0, keyring::serialize(keyring::Contents{})), prefixed(1, keyring::seal(f.key32, f.id16, plain))};
}

bool run_archive(const uint8_t* data, size_t size) {
    auto& f = fixed();
    auto rec = archive::open_entry(f.key32, f.id16, 7, Bytes(data, data + size));
    if (rec) chat::parse_record(*rec);
    return rec.has_value();
}

std::vector<Bytes> seeds_archive() {
    auto& f = fixed();
    return {archive::seal_entry(f.key32, f.id16, 7, signed_record(chat::RecordType::Text, Bytes{'h', 'i'}))};
}

// --- The encrypted connection's handshake ---

bool run_channel(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    auto& f = fixed();
    const Bytes in(data + 1, data + size);
    switch (data[0] % 4) {
        case 0: {
            auto h = securechannel::decode_client_hello(in);
            if (h && securechannel::encode(*h) != in) violated("client hello");
            securechannel::ServerHandshake server(f.sig);
            Bytes reply;
            return server.reply(in, reply);
        }
        case 1: {
            auto h = securechannel::decode_server_hello(in);
            if (h && securechannel::encode(*h) != in) violated("server hello");
            securechannel::ClientHandshake client;
            client.hello();
            Bytes finish, id;
            securechannel::Keys keys;
            std::string error;
            // A relay's answer is signed together with the client's own hello, so a recorded one can never be accepted by a new
            // client: this exercises the checks, and must refuse it.
            if (client.finish(in, Bytes(), finish, keys, id, error)) violated("a server hello accepted by a client that never sent its hello");
            return h.has_value();
        }
        case 2: {
            auto h = securechannel::decode_client_finish(in);
            if (h && securechannel::encode(*h) != in) violated("client finish");
            return h.has_value();
        }
        default: {  // a sealed frame
            securechannel::Cipher c(securechannel::Keys{f.key32, R(32, 3)}, true);
            return c.open(in).has_value();
        }
    }
}

std::vector<Bytes> seeds_channel() {
    auto& f = fixed();
    securechannel::ClientHandshake client;
    securechannel::ServerHandshake server(f.sig);
    const Bytes hello = client.hello();
    Bytes reply, finish, id;
    securechannel::Keys keys;
    std::string error;
    server.reply(hello, reply);
    client.finish(reply, Bytes(), finish, keys, id, error);
    securechannel::Cipher relay_side(securechannel::Keys{R(32, 3), f.key32}, false);
    return {prefixed(0, hello), prefixed(1, reply), prefixed(2, finish), prefixed(3, relay_side.seal(R(100)))};
}

// --- Identity bundles, and text people paste: contact cards, share links, invites, addresses ---

bool run_bundle(const uint8_t* data, size_t size) { return parse_identity_bundle(Bytes(data, data + size)).has_value(); }

std::vector<Bytes> seeds_bundle() {
    auto& f = fixed();
    return {create_identity_bundle(f.sig.public_key, f.kem.public_key, "Fuzz", "relay.example:9000", 1700000000, f.sig.private_key)};
}

bool run_text(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    const std::string in(reinterpret_cast<const char*>(data + 1), size - 1);
    switch (data[0] % 4) {
        case 0: return decode_any_contact_card(in).has_value() | decode_contact_card(in).has_value();
        case 1: return parse_share_link(in).has_value();
        case 2: return parse_relay_invite(in).has_value();
        default: return parse_server_address(in).has_value();
    }
}

std::vector<Bytes> seeds_text() {
    auto& f = fixed();
    auto str = [](uint8_t sel, const std::string& s) { Bytes b{sel}; b.insert(b.end(), s.begin(), s.end()); return b; };
    const Bytes bundle = seeds_bundle()[0];
    ContactCard card{"Fuzz", f.kem.public_key, f.sig.public_key, "10.0.0.1"};
    RelayInvite invite{ServerAddress{"10.0.0.1", 9000}, R(32), R(16)};
    return {str(0, encode_contact_card(card)), str(0, encode_contact_card_v2(bundle)), str(0, encode_contact_card_v3(bundle, R(32))),
            str(1, build_share_link(ServerAddress{"10.0.0.1", 9000}, std::string(32, 'a'))), str(2, build_relay_invite(invite)), str(3, "relay.example:9000")};
}

// --- The older transfer-ID file transfer ---

bool run_v2(const uint8_t* data, size_t size) {
    if (size == 0) return false;
    const uint8_t* p = data + 1;
    const size_t n = size - 1;
    switch (data[0] % 3) {
        case 0: return deserialize_file_header(p, n).has_value();
        case 1: return deserialize_file_metadata(p, n).has_value();
        default: return deserialize_file_chunk(p, n).has_value();
    }
}

std::vector<Bytes> seeds_v2() {
    FileHeader h{};
    FileMetadata m{};
    ::FileChunk c{};
    c.data = R(100);
    return {prefixed(0, serialize_file_header(h)), prefixed(1, serialize_file_metadata(m)), prefixed(2, serialize_file_chunk(c))};
}

}  // namespace

const std::vector<Target>& targets() {
    static const std::vector<Target> t = {
        {"relay", run_relay, seeds_relay},       {"records", run_records, seeds_records}, {"envelope", run_envelope, seeds_envelope},
        {"prekey", run_prekey, seeds_prekey},    {"keyring", run_keyring, seeds_keyring}, {"archive", run_archive, seeds_archive},
        {"channel", run_channel, seeds_channel}, {"bundle", run_bundle, seeds_bundle},    {"text", run_text, seeds_text},
        {"v2", run_v2, seeds_v2},
    };
    return t;
}

void run_one(const uint8_t* data, size_t size) {
    if (size == 0) return;
    const auto& t = targets();
    t[data[0] % t.size()].run(data + 1, size - 1);
}

}  // namespace fuzz
