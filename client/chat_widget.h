#pragma once

#include <QWidget>

#include <atomic>
#include <filesystem>
#include <functional>
#include <optional>
#include <memory>
#include <string>
#include <thread>

#include "messaging_engine.h"
#include "chat_entry.h"
#include "message_view.h"

class QCheckBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPushButton;
class QTimer;

// The Chats tab: contact list, group list, conversation view, message requests, relay setup and the
// list of contact cards the user has handed out. It owns the MessagingEngine and the worker thread that
// pumps it; the UI thread only ever reads state from the engine and queues messages into it.
class ChatWidget : public QWidget {
public:
    ChatWidget(KeyStore& keys, const std::filesystem::path& history_path, QWidget* parent = nullptr);
    ~ChatWidget() override;
    // Called with the relay's address ("host:port") once messaging has been set up on it, so the Files tab can use the same one.
    void set_on_relay_chosen(std::function<void(const QString&)> f) { on_relay_chosen_ = std::move(f); }
    // Called with how many messages are waiting to be read, across all chats, whenever that changes.
    void set_on_unread_changed(std::function<void(size_t)> f) { on_unread_changed_ = std::move(f); }
    void refresh_now() { refresh(); }  // for when this tab is shown again: what was waiting is now seen

    bool available() const { return engine_ != nullptr; }
    bool is_set_up() const { return engine_ && engine_->is_set_up(); }

    // Makes a contact card with a fresh send token for one person and puts it on the clipboard.
    void copy_card_to_clipboard();
    // A new messaging card (asks who it is for; each card carries its own permission to message us), or nothing if cancelled.
    std::optional<QString> make_card_text();
    // The Add contact button: the main window owns adding contacts.
    void set_on_add_contact(std::function<void()> f) { on_add_contact_ = std::move(f); }
    // For the main window's Settings.
    void open_setup();
    void setup_with_invite(const QString& invite);  // the same checks and confirmation as Set up messaging…
    void open_relay_invites();
    void open_cards_issued();
    void open_restore();
    QString messaging_status() const;
    // For Home (UX step 5).
    void set_on_changed(std::function<void()> f) { on_changed_ = std::move(f); }  // after each look for news
    QString waiting_summary() const;  // "1 message request · 2 group invitations", or empty
    size_t unread_total() const { return last_unread_; }
    std::vector<ChatEntry> recent_entries(int count) const;  // most recent first, as the Chats list shows them
    void open_conversation(const QString& key);  // a key from recent_entries

    // Call after contacts were added or changed from outside this tab.
    void refresh();

    // The user compared this contact's fingerprint with them (the add-contact dialog asked).
    void mark_verified(const std::string& fingerprint);

private:
    void setup_messaging(const QString& preset_invite = QString());  // empty: ask for it
    void review_requests();
    void create_group_dialog();
    void make_relay_invite();
    void restore_history();
    void attach_file();
    void render_privates();
    void render_conversations();
    void sync_conversation_selection();
    void render_private_messages(bool force_scroll);
    void select_private(const QString& chat_id);
    void start_private_chat();
    bool open_details(const MessageLine& line);
    void report_unread();
    void show_attachment(const QString& file_id);
    void review_deletions();
    void request_delete_chat();
    void review_group_invites();
    void show_cards_issued();
    void revoke_access_for_current();
    void send_current();
    void select_contact(const QString& fingerprint);
    void select_group(const QString& group_id);
    void apply_receipt_settings();
    void refresh_if_changed();
    void render_chats();
    void render_groups();
    void render_messages(bool force_scroll);
    void render_group_messages(bool force_scroll);
    void show_group_delivery(const QString& message_id);
    void people_clicked();
    void show_group_members();
    void verify_person(const std::string& fingerprint, const QString& name);
    void update_header();

    KeyStore& keys_;
    std::unique_ptr<MessagingEngine> engine_;
    std::thread worker_;
    std::atomic<bool> stop_{false};

    QLabel* status_label_ = nullptr;
    QLabel* notice_label_ = nullptr;
    QPushButton* setup_button_ = nullptr;
    QPushButton* requests_button_ = nullptr;
    QPushButton* cards_button_ = nullptr;
    QPushButton* new_group_button_ = nullptr;
    QPushButton* new_private_button_ = nullptr;  // start a Private (disappearing) chat
    QPushButton* relay_invite_button_ = nullptr;
    QPushButton* restore_button_ = nullptr;
    QPushButton* attach_button_ = nullptr;   // choose a file to send in the chat on screen
    std::function<void(const QString&)> on_relay_chosen_;
    std::function<void()> on_add_contact_;
    std::function<void()> on_changed_;
    std::function<void(size_t)> on_unread_changed_;
    size_t last_unread_ = static_cast<size_t>(-1);
    bool animating_ = false;                 // an upload or download is under way: redraw now and then to show its progress
    QPushButton* deletions_button_ = nullptr;     // requests from others to delete a chat or messages
    QPushButton* delete_chat_button_ = nullptr;   // ask everyone to delete the chat on screen
    QPushButton* invites_button_ = nullptr;
    QPushButton* add_contact_button_ = nullptr;
    // UX step 2: the visible controls. The original buttons and boxes still exist, inside `hidden_` (a hidden holder, so nothing
    // can show them again), and these trigger them, so every confirmation and check behind them runs exactly as before.
    QWidget* hidden_ = nullptr;
    QPushButton* new_button_ = nullptr;       // New ▾: group, Private chat
    QPushButton* waiting_button_ = nullptr;   // shown only when requests, invitations or deletion requests are waiting
    QPushButton* options_button_ = nullptr;   // ⋯ in the chat header
    QListWidget* conversations_ = nullptr;    // one list: contacts, groups and Private chats, most recent first
    std::vector<ChatEntry> conversation_entries_;  // what it shows
    QLabel* header_icon_ = nullptr;           // an hourglass beside a Private chat's name (when icons are available)
    QLabel* header_note_ = nullptr;           // the header's smaller second part: trust, members, a Private chat's limits
    void set_header(const QString& text);     // first line: the title; the rest: the note
    size_t waiting_requests_ = 0, waiting_invitations_ = 0, waiting_deletions_ = 0;
    QString last_card_label_;  // who the last card made was for (for the note shown after copying it)
    QListWidget* contacts_ = nullptr;
    QLabel* groups_label_ = nullptr;
    QListWidget* groups_ = nullptr;
    QLabel* private_label_ = nullptr;
    QListWidget* privates_ = nullptr;  // Private chats, kept apart from the saved ones
    QLabel* header_label_ = nullptr;
    QCheckBox* delivery_box_ = nullptr;
    QCheckBox* read_box_ = nullptr;
    QPushButton* revoke_button_ = nullptr;
    QPushButton* people_button_ = nullptr;  // "Members…" for a group, "Verify…" for a contact
    MessageView* messages_ = nullptr;  // the chat on screen, as selectable text (G1)
    QLineEdit* input_ = nullptr;
    QPushButton* send_button_ = nullptr;
    QTimer* timer_ = nullptr;

    QString current_fp_;     // the contact being looked at, or empty
    QString current_group_;  // the group being looked at (its ID), or empty. Never both.
    QString current_private_;  // the Private chat being looked at (its ID), or empty. Only one of the three is ever set.
    uint64_t last_revision_ = 0;
    size_t shown_messages_ = 0;
    bool updating_ui_ = false;
};
