#include "private_store.h"

#include <sqlite3.h>
#include <stdexcept>

#include "crypto_engine.h"
#include "protocol.h"

namespace {

struct Statement {
    sqlite3_stmt* s = nullptr;
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) != SQLITE_OK) throw std::runtime_error(std::string("Private store: ") + sqlite3_errmsg(db));
    }
    ~Statement() { sqlite3_finalize(s); }
    Statement& blob(int i, const std::vector<uint8_t>& b) { sqlite3_bind_blob(s, i, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT); return *this; }
    Statement& text(int i, const std::string& t) { sqlite3_bind_text(s, i, t.c_str(), -1, SQLITE_TRANSIENT); return *this; }
    Statement& i64(int i, int64_t v) { sqlite3_bind_int64(s, i, v); return *this; }
    Statement& opt(int i, std::optional<int64_t> v) { if (v) sqlite3_bind_int64(s, i, *v); else sqlite3_bind_int64(s, i, -1); return *this; }
    bool step() {
        int rc = sqlite3_step(s);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw std::runtime_error("Private store: a query failed");
    }
    std::vector<uint8_t> column_blob(int i) {
        const auto* p = static_cast<const uint8_t*>(sqlite3_column_blob(s, i));
        return p ? std::vector<uint8_t>(p, p + sqlite3_column_bytes(s, i)) : std::vector<uint8_t>();
    }
    std::string column_text(int i) {
        const auto* p = static_cast<const char*>(sqlite3_column_blob(s, i));
        return p ? std::string(p, static_cast<size_t>(sqlite3_column_bytes(s, i))) : std::string();
    }
    int64_t column_i64(int i) { return sqlite3_column_int64(s, i); }
};

const char KEY_AAD[] = "pq-suite v3 private message key";
const char BODY_AAD[] = "pq-suite v3 private message";

std::vector<uint8_t> aad_of(const char* label, const std::vector<uint8_t>& conv, const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> a;
    write_string(a, label);
    write_blob(a, conv);
    write_blob(a, msg);
    return a;
}

std::optional<int64_t> opt_of(int64_t v) { return v < 0 ? std::nullopt : std::optional<int64_t>(v); }

}  // namespace

PrivateStore::PrivateStore(const std::filesystem::path& path, const Bytes& key) : key_(key) {
    if (key_.size() != 32) throw std::runtime_error("Private store: the key is not valid");
    open_or_recreate(path);
}

PrivateStore::~PrivateStore() {
    if (db_) sqlite3_close(db_);
    CryptoEngine::secure_wipe(key_);
}

void PrivateStore::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string message = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("Private store: " + message);
    }
}

void PrivateStore::open_or_recreate(const std::filesystem::path& path) {
    for (int attempt = 0; attempt < 2; attempt++) {
        if (sqlite3_open_v2(path.string().c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK) {
            try {
                exec("PRAGMA secure_delete=ON; PRAGMA journal_mode=MEMORY; PRAGMA synchronous=FULL;"
                     "CREATE TABLE IF NOT EXISTS chats(id BLOB PRIMARY KEY, contact_fp TEXT NOT NULL, mode INTEGER NOT NULL, timer INTEGER NOT NULL,"
                     "  created_at INTEGER NOT NULL, started_by_me INTEGER NOT NULL);"
                     "CREATE TABLE IF NOT EXISTS messages(conv_id BLOB NOT NULL, message_id BLOB NOT NULL, outgoing INTEGER NOT NULL,"
                     "  sent_at INTEGER NOT NULL, received_at INTEGER NOT NULL, displayed_at INTEGER NOT NULL DEFAULT -1, expires_at INTEGER NOT NULL DEFAULT -1,"
                     "  status INTEGER NOT NULL DEFAULT 0, key_sealed BLOB NOT NULL, body BLOB NOT NULL, PRIMARY KEY(conv_id, message_id));"
                     "CREATE TABLE IF NOT EXISTS revocations(conv_id BLOB NOT NULL, message_id BLOB NOT NULL, mailbox_id BLOB NOT NULL, envelope_id BLOB NOT NULL, secret BLOB NOT NULL);"
                     "SELECT COUNT(*) FROM messages;");
                std::error_code ec;
                std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace, ec);
                return;
            } catch (const std::exception&) {
            }
        }
        // Damaged: start afresh. Private messages are meant to be gone sooner or later anyway; nothing else depends on them.
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    throw std::runtime_error("Private store: could not be opened");
}

PrivateStore::Bytes PrivateStore::seal(const Bytes& key, const Bytes& plain, const Bytes& aad) {
    Bytes nonce = CryptoEngine::random_bytes(12);
    Bytes out = nonce;
    Bytes ct = CryptoEngine::encrypt(key, nonce, plain, aad);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

std::optional<PrivateStore::Bytes> PrivateStore::unseal(const Bytes& key, const Bytes& sealed, const Bytes& aad) {
    if (sealed.size() < 12 + 16) return std::nullopt;
    try {
        return CryptoEngine::decrypt(key, Bytes(sealed.begin(), sealed.begin() + 12), Bytes(sealed.begin() + 12, sealed.end()), aad);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool PrivateStore::add_chat(const Chat& c) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement(db_, "INSERT OR IGNORE INTO chats(id, contact_fp, mode, timer, created_at, started_by_me) VALUES(?, ?, ?, ?, ?, ?)")
        .blob(1, c.id).text(2, c.contact_fp).i64(3, c.mode).i64(4, c.timer).i64(5, c.created_at).i64(6, c.started_by_me ? 1 : 0).step();
    return sqlite3_changes(db_) > 0;
}

std::optional<PrivateStore::Chat> PrivateStore::chat(const Bytes& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT id, contact_fp, mode, timer, created_at, started_by_me FROM chats WHERE id = ?");
    s.blob(1, id);
    if (!s.step()) return std::nullopt;
    return Chat{s.column_blob(0), s.column_text(1), static_cast<int>(s.column_i64(2)), s.column_i64(3), s.column_i64(4), s.column_i64(5) != 0};
}

std::vector<PrivateStore::Chat> PrivateStore::chats() {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT id, contact_fp, mode, timer, created_at, started_by_me FROM chats ORDER BY created_at, rowid");
    std::vector<Chat> out;
    while (s.step()) out.push_back(Chat{s.column_blob(0), s.column_text(1), static_cast<int>(s.column_i64(2)), s.column_i64(3), s.column_i64(4), s.column_i64(5) != 0});
    return out;
}

bool PrivateStore::add_message(const Message& m) {
    std::lock_guard<std::mutex> lock(mutex_);
    Bytes message_key = CryptoEngine::random_bytes(32);
    const Bytes body = seal(message_key, m.record, aad_of(BODY_AAD, m.conversation_id, m.message_id));
    const Bytes key_sealed = seal(key_, message_key, aad_of(KEY_AAD, m.conversation_id, m.message_id));
    CryptoEngine::secure_wipe(message_key);
    Statement(db_, "INSERT OR IGNORE INTO messages(conv_id, message_id, outgoing, sent_at, received_at, displayed_at, expires_at, status, key_sealed, body) "
                   "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .blob(1, m.conversation_id).blob(2, m.message_id).i64(3, m.outgoing ? 1 : 0).i64(4, m.sent_at).i64(5, m.received_at).opt(6, m.displayed_at).opt(7, m.expires_at)
        .i64(8, m.status).blob(9, key_sealed).blob(10, body).step();
    return sqlite3_changes(db_) > 0;
}

std::optional<PrivateStore::Message> PrivateStore::read_row(void* statement, const Bytes& conversation_id) {
    auto& s = *static_cast<Statement*>(statement);
    Message m;
    m.conversation_id = conversation_id;
    m.message_id = s.column_blob(0);
    m.outgoing = s.column_i64(1) != 0;
    m.sent_at = s.column_i64(2);
    m.received_at = s.column_i64(3);
    m.displayed_at = opt_of(s.column_i64(4));
    m.expires_at = opt_of(s.column_i64(5));
    m.status = static_cast<int>(s.column_i64(6));
    auto message_key = unseal(key_, s.column_blob(7), aad_of(KEY_AAD, conversation_id, m.message_id));
    if (!message_key) return std::nullopt;
    auto record = unseal(*message_key, s.column_blob(8), aad_of(BODY_AAD, conversation_id, m.message_id));
    CryptoEngine::secure_wipe(*message_key);
    if (!record) return std::nullopt;
    m.record = std::move(*record);
    return m;
}

std::vector<PrivateStore::Message> PrivateStore::messages(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT message_id, outgoing, sent_at, received_at, displayed_at, expires_at, status, key_sealed, body FROM messages WHERE conv_id = ? ORDER BY sent_at, rowid");
    s.blob(1, conversation_id);
    std::vector<Message> out;
    while (s.step())
        if (auto m = read_row(&s, conversation_id)) out.push_back(std::move(*m));
    return out;
}

std::optional<PrivateStore::Message> PrivateStore::message(const Bytes& conversation_id, const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT message_id, outgoing, sent_at, received_at, displayed_at, expires_at, status, key_sealed, body FROM messages WHERE conv_id = ? AND message_id = ?");
    s.blob(1, conversation_id).blob(2, message_id);
    if (!s.step()) return std::nullopt;
    return read_row(&s, conversation_id);
}

void PrivateStore::set_displayed(const Bytes& conversation_id, const Bytes& message_id, int64_t displayed_at, std::optional<int64_t> expires_at) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement(db_, "UPDATE messages SET displayed_at = ?, expires_at = ? WHERE conv_id = ? AND message_id = ? AND displayed_at = -1")
        .i64(1, displayed_at).opt(2, expires_at).blob(3, conversation_id).blob(4, message_id).step();
}

void PrivateStore::set_expires(const Bytes& conversation_id, const Bytes& message_id, std::optional<int64_t> expires_at) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement(db_, "UPDATE messages SET expires_at = ? WHERE conv_id = ? AND message_id = ?").opt(1, expires_at).blob(2, conversation_id).blob(3, message_id).step();
}

void PrivateStore::set_status(const Bytes& conversation_id, const Bytes& message_id, int status) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement(db_, "UPDATE messages SET status = ? WHERE conv_id = ? AND message_id = ?").i64(1, status).blob(2, conversation_id).blob(3, message_id).step();
}

size_t PrivateStore::secure_erase(const char* where, const std::vector<Bytes>& blobs, const std::vector<int64_t>& ints) {
    // The message's own key first (without it the message can't be read), then the message, then the rows themselves.
    const std::string update = std::string("UPDATE messages SET key_sealed = zeroblob(length(key_sealed)), body = zeroblob(length(body)) WHERE ") + where;
    const std::string remove = std::string("DELETE FROM messages WHERE ") + where;
    size_t gone = 0;
    exec("BEGIN");
    for (const std::string* sql : {&update, &remove}) {
        Statement s(db_, sql->c_str());
        int i = 1;
        for (const auto& b : blobs) s.blob(i++, b);
        for (int64_t v : ints) s.i64(i++, v);
        s.step();
        gone = static_cast<size_t>(sqlite3_changes(db_));
    }
    // A message that is gone needs no way of taking its envelope back.
    exec("DELETE FROM revocations WHERE NOT EXISTS (SELECT 1 FROM messages m WHERE m.conv_id = revocations.conv_id AND m.message_id = revocations.message_id)");
    exec("COMMIT");
    return gone;
}

void PrivateStore::add_revocation(const Bytes& conversation_id, const Bytes& message_id, const Revocation& r) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement(db_, "INSERT INTO revocations(conv_id, message_id, mailbox_id, envelope_id, secret) VALUES(?, ?, ?, ?, ?)")
        .blob(1, conversation_id).blob(2, message_id).blob(3, r.mailbox_id).blob(4, r.envelope_id).blob(5, r.secret).step();
}

std::vector<PrivateStore::Revocation> PrivateStore::revocations(const Bytes& conversation_id, const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement s(db_, "SELECT mailbox_id, envelope_id, secret FROM revocations WHERE conv_id = ? AND message_id = ?");
    s.blob(1, conversation_id).blob(2, message_id);
    std::vector<Revocation> out;
    while (s.step()) out.push_back({s.column_blob(0), s.column_blob(1), s.column_blob(2)});
    return out;
}

size_t PrivateStore::expire(int64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    return secure_erase("expires_at >= 0 AND expires_at <= ?", {}, {now});
}

bool PrivateStore::erase_message(const Bytes& conversation_id, const Bytes& message_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return secure_erase("conv_id = ? AND message_id = ?", {conversation_id, message_id}, {}) > 0;
}

size_t PrivateStore::erase_chat(const Bytes& conversation_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t gone = secure_erase("conv_id = ?", {conversation_id}, {});
    Statement(db_, "DELETE FROM chats WHERE id = ?").blob(1, conversation_id).step();
    return gone;
}
