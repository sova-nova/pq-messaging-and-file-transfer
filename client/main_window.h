#pragma once

#include <QMainWindow>
#include <QString>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "key_store.h"
#include "sharing.h"
#include "transfer_engine.h"

class ChatWidget;
class QComboBox;
class QDialog;
class QListWidget;
class QTabWidget;
class QGroupBox;
class QVBoxLayout;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private:
    QLabel* status_label_ = nullptr;
    QLabel* fingerprint_label_ = nullptr;
    QLineEdit* server_edit_ = nullptr;
    QComboBox* recipient_combo_ = nullptr;
    QPushButton* add_contact_button_ = nullptr;
    QPushButton* remove_contact_button_ = nullptr;
    QLabel* key_status_label_ = nullptr;
    QPushButton* key_protection_button_ = nullptr;
    QPushButton* copy_card_button_ = nullptr;
    QPushButton* export_keys_button_ = nullptr;
    QPushButton* send_button_ = nullptr;
    QPushButton* receive_button_ = nullptr;
    QPushButton* cancel_button_ = nullptr;
    QPushButton* copy_link_button_ = nullptr;
    QPushButton* copy_id_button_ = nullptr;
    QPushButton* open_downloads_button_ = nullptr;
    QProgressBar* progress_bar_ = nullptr;
    QLabel* transfer_id_label_ = nullptr;

    ChatWidget* chat_widget_ = nullptr;  // the Chats tab; null until the keys are ready
    std::unique_ptr<KeyStore> keystore_;
    TransferEngine engine_;
    std::thread worker_thread_;
    std::atomic<bool> busy_{false};
    QString current_transfer_id_;
    QString current_share_link_;
    ServerAddress last_server_;  // relay used for the most recent upload

    void start_send();
    void start_receive();
    bool setup_keys(std::string& problem);
    bool unlock_keys(std::string& problem);
    std::string keychain_account() const;
    void remember_passphrase(const std::string& passphrase);
    void update_key_status();
    void open_settings();
    void update_relay_label();
    // UX step 5: Home.
    void build_home();
    // UX step 6: the first-run guide (new users only). Welcome, name, key protection, messaging invite, then Done.
    struct FirstRunChoices {
        QString name;
        bool protect = false;
        std::string passphrase;
        bool remember = false;
        QString invite;            // empty: not now
        bool add_contact = false;  // "Add your first contact" on the last step
    };
    bool run_first_run_guide(FirstRunChoices& out);  // false: closed before the end
    QString pending_invite_;          // used once the window exists (messaging needs the Chats tab)
    bool pending_add_contact_ = false;
    void refresh_home();
    QTabWidget* tabs_ = nullptr;
    QWidget* files_page_ = nullptr;
    QWidget* home_page_ = nullptr;
    QLabel* home_status_ = nullptr;
    QPushButton* home_setup_button_ = nullptr;
    QWidget* home_waiting_ = nullptr;
    QLabel* home_waiting_text_ = nullptr;
    QPushButton* home_chats_button_ = nullptr;
    QLabel* home_chats_text_ = nullptr;  // the Open chats tile's second line: the unread count
    QListWidget* home_recent_ = nullptr;
    QLabel* home_recent_empty_ = nullptr;
    QString home_signature_;  // what Home last showed, so it is only redrawn when something changed
    // UX step 4: the guided Files tab.
    QLineEdit* receive_edit_ = nullptr;        // the Receive card's paste box
    QWidget* progress_row_ = nullptr;          // progress and Cancel: only while a transfer runs
    QGroupBox* result_box_ = nullptr;          // the link to give: only once a send has one
    QLabel* relay_label_ = nullptr;            // "Using relay host:port"
    QPushButton* change_relay_button_ = nullptr;
    QDialog* settings_dialog_ = nullptr;          // fingerprint, card, key files, key protection, messaging extras
    QVBoxLayout* settings_layout_ = nullptr;
    QWidget* key_warning_ = nullptr;              // the Files tab's one line about unprotected keys, shown only then
    QLabel* settings_messaging_status_ = nullptr;
    QPushButton* settings_setup_button_ = nullptr;
    QPushButton* settings_invites_button_ = nullptr;
    QPushButton* settings_cards_button_ = nullptr;
    QPushButton* settings_restore_button_ = nullptr;
    void set_passphrase_action();
    void change_passphrase_action();
    void remove_passphrase_action();
    void forget_saved_passphrase();

    void add_contact();  // the Add a contact dialog
    // Adds (or updates) a contact from a pasted card; `chosen_name` empty: the card's suggestion is offered. True if done.
    bool add_contact_from_card_text(const QString& text, const QString& chosen_name);
    void add_contact_from_files();
    std::optional<QString> ask_contact_name(const QString& suggested);
    bool confirm_contact_name(const QString& name);  // valid, and (if it exists) the user agrees to replace it
    // `bundle` is set when the contact came from a v2 card, whose encryption key is signed. True if saved.
    bool finish_add_contact(const QString& name,
                            const std::vector<uint8_t>& pub_kem,
                            const std::vector<uint8_t>& pub_dsa,
                            const std::string& card_server,
                            const IdentityBundle* bundle,
                            const std::vector<uint8_t>& send_token = std::vector<uint8_t>());
    void remove_contact();
    void copy_contact_card();
    void save_contact_card();
    std::optional<QString> own_card_text();  // our card (a messaging card when messaging is set up), or nothing if cancelled
    void show_card_note(const QString& where);
    void export_keys();
    void copy_share_link();
    void copy_transfer_id();
    void open_downloads();
    void refresh_contacts();
    void save_server_setting();

    void run_in_background(std::function<void()> job);
    std::vector<uint8_t> trusted_relay_for(const std::string& host, uint16_t port);
    void remember_relay(const std::string& host, uint16_t port, const std::vector<uint8_t>& pin);
    void set_busy(bool busy);

    void update_status(const std::string& msg);
    void update_progress(double fraction);
    void show_error(const std::string& error);
    void show_complete(const std::string& filepath);
    void show_transfer_id(const std::string& id);
};
