#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

// Private chats (M7): their own encrypted store, never the Saved history, never archived, never in the keyring, never restored.
// Each message is sealed under its own random key, and that key is itself sealed under the store's key. When a message expires
// (or is deleted or retracted) its key is overwritten and deleted first, then the message: with SQLite's secure deletion on and
// the journal kept in memory, nothing readable is left in the file (a solid-state disk may still keep old copies of its own).
class PrivateStore {
public:
    using Bytes = std::vector<uint8_t>;
    enum Mode : int { FromSending = 1, FromReading = 2 };

    struct Chat {
        Bytes id;                // the Private chat's own conversation ID (random, chosen by whoever started it)
        std::string contact_fp;  // the other person
        int mode = FromSending;
        int64_t timer = 0;       // seconds: one of the allowed timers
        int64_t created_at = 0;
        bool started_by_me = false;
    };
    struct Message {
        Bytes conversation_id;
        Bytes message_id;
        bool outgoing = false;
        int64_t sent_at = 0;
        int64_t received_at = 0;
        std::optional<int64_t> displayed_at;  // when this device first showed it (after-reading chats count from here)
        std::optional<int64_t> expires_at;    // when it goes; not yet known for an outgoing after-reading message awaiting receipts
        Bytes record;                         // the signed record
        int status = 0;                       // delivery state, for outgoing messages
    };

    PrivateStore(const std::filesystem::path& path, const Bytes& key);
    ~PrivateStore();
    PrivateStore(const PrivateStore&) = delete;
    PrivateStore& operator=(const PrivateStore&) = delete;

    bool add_chat(const Chat& chat);  // false if that chat is already known
    std::optional<Chat> chat(const Bytes& id);
    std::vector<Chat> chats();

    bool add_message(const Message& m);  // false if already there (a replay)
    std::vector<Message> messages(const Bytes& conversation_id);  // oldest first; only ones still readable
    std::optional<Message> message(const Bytes& conversation_id, const Bytes& message_id);
    void set_displayed(const Bytes& conversation_id, const Bytes& message_id, int64_t displayed_at, std::optional<int64_t> expires_at);
    void set_expires(const Bytes& conversation_id, const Bytes& message_id, std::optional<int64_t> expires_at);
    void set_status(const Bytes& conversation_id, const Bytes& message_id, int status);

    // What is needed to take a sent message's envelope back from the recipient's relay while it is still waiting there.
    struct Revocation {
        Bytes mailbox_id;
        Bytes envelope_id;
        Bytes secret;
    };
    void add_revocation(const Bytes& conversation_id, const Bytes& message_id, const Revocation& r);
    std::vector<Revocation> revocations(const Bytes& conversation_id, const Bytes& message_id);

    size_t expire(int64_t now);  // erases every message whose time has come; returns how many
    bool erase_message(const Bytes& conversation_id, const Bytes& message_id);  // deleting one's own copy, or a retraction
    size_t erase_chat(const Bytes& conversation_id);                             // the chat and everything in it

private:
    void open_or_recreate(const std::filesystem::path& path);
    void exec(const char* sql);
    size_t secure_erase(const char* where, const std::vector<Bytes>& blobs, const std::vector<int64_t>& ints);
    Bytes seal(const Bytes& key, const Bytes& plain, const Bytes& aad);
    std::optional<Bytes> unseal(const Bytes& key, const Bytes& sealed, const Bytes& aad);
    std::optional<Message> read_row(void* statement, const Bytes& conversation_id);
    sqlite3* db_ = nullptr;
    Bytes key_;
    std::mutex mutex_;
};
