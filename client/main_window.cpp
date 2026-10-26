#include "main_window.h"
#include "scope_exit.h"
#include "app_style.h"
#include "chat_entry.h"
#include "icons.h"
#include "crypto_engine.h"
#include "chat_widget.h"
#include "key_dialogs.h"
#include "keychain.h"
#include "protocol.h"  // bytes_to_hex, hex_to_bytes (the Files tab's remembered relay IDs)

#include <QAction>
#include <QSizePolicy>
#include <QTimer>
#include <QStackedWidget>
#include <QRadioButton>
#include <QTabBar>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QGroupBox>
#include <QDialog>
#include <QClipboard>
#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QProgressBar>
#include <QTabWidget>
#include <QPushButton>
#include <QSettings>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>
#include <filesystem>
#include <optional>

namespace {

const char* const SERVER_SETTING = "server";
const char* const DEFAULT_SERVER = "127.0.0.1:9000";

QString qstr(const std::string& s) { return QString::fromStdString(s); }

QString formatted_fingerprint(const std::string& fp) {
    return qstr(CryptoEngine::format_fingerprint(fp));
}

std::vector<uint8_t> read_small_file(const QString& path, qint64 max_size) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly) || f.size() <= 0 || f.size() > max_size) return {};
    QByteArray data = f.readAll();
    return std::vector<uint8_t>(data.begin(), data.end());
}

// The server field as a parsed address, if it holds a valid one.
std::optional<ServerAddress> configured_server(const QLineEdit* edit) {
    return parse_server_address(edit->text().toStdString());
}

QString default_display_name() {
    QString name = qEnvironmentVariable("USER");
    if (name.isEmpty()) name = qEnvironmentVariable("USERNAME");
    return name;
}

const char* const KEY_PROTECTION_DECIDED = "key_protection_decided";

// Explains key protection, and what the keychain does for convenience, before asking.
QString protection_explanation(const QString& heading) {
    QString text = heading +
        "\n\nYour private keys let you read files that are sent to you and prove that files from you "
        "are really yours. If someone copies them, for example from a stolen laptop or an unprotected "
        "backup, they can read everything sent to you. A passphrase locks them.\n\n";
    if (keychain::available()) {
        text += "With \"Remember on this computer\" ticked, the passphrase is kept in your system's "
                "keychain (Windows Credential Manager, macOS Keychain or the Linux keyring). You will "
                "rarely have to type it again, typically only after reinstalling or on a new computer.\n\n";
    } else {
        text += "You will be asked for the passphrase each time you start the app.\n\n";
    }
    text += "A forgotten passphrase cannot be recovered. Use at least 8 characters; a few random words work well.";
    return text;
}

QLabel* plain_label(const QString& text, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setTextFormat(Qt::PlainText);  // never interpret server/sender text as HTML
    label->setWordWrap(true);
    return label;
}

}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("PQ File Transfer");
    setMinimumSize(480, 560);

    // Two tabs: the existing file transfer, and chats. Everything below up to the Chats tab is the
    // Files page, built into `layout`.
    auto* tabs = new QTabWidget(this);
    tabs_ = tabs;
    setCentralWidget(tabs);
    auto* files_page = new QWidget(tabs);
    files_page_ = files_page;
    auto* layout = new QVBoxLayout(files_page);
    tabs->addTab(files_page, "Files");

    status_label_ = plain_label("Status: Ready", this);
    status_label_->setProperty("role", "muted");

    std::string key_problem;
    try {
        keystore_ = std::make_unique<KeyStore>();
        if (!setup_keys(key_problem)) {
            keystore_.reset();
            layout->addWidget(status_label_);
            layout->addStretch();
            show_error(key_problem);
            return;
        }
    } catch (const std::exception& e) {
        keystore_.reset();
        layout->addWidget(status_label_);
        layout->addStretch();
        show_error(std::string("Key setup failed: ") + e.what());
        return;
    }
    engine_.set_keystore(keystore_.get());  // transfers use the unlocked keys held by the app

    // --- Settings (UX step 3): your identity and key protection live here, off the main screens. The widgets are the same ones
    // as before, so everything that updates or enables them still does. Messaging extras are added once the Chats tab exists.
    settings_dialog_ = new QDialog(this);
    settings_dialog_->setWindowTitle("Settings");
    settings_dialog_->setMinimumWidth(560);
    settings_layout_ = new QVBoxLayout(settings_dialog_);
    auto* identity_box = new QGroupBox("Your identity", settings_dialog_);
    auto* identity_box_layout = new QVBoxLayout(identity_box);
    settings_layout_->addWidget(identity_box);
    auto* fingerprint_hint = plain_label("Your fingerprint. Contacts check it with you (in person or on a call) before trusting your keys:", identity_box);
    fingerprint_hint->setWordWrap(true);
    identity_box_layout->addWidget(fingerprint_hint);
    fingerprint_label_ = plain_label(formatted_fingerprint(keystore_->own_fingerprint()), identity_box);
    fingerprint_label_->setAlignment(Qt::AlignCenter);
    fingerprint_label_->setStyleSheet("font-family: monospace;");
    fingerprint_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    identity_box_layout->addWidget(fingerprint_label_);

    auto* identity_layout = new QHBoxLayout();
    copy_card_button_ = new QPushButton("Copy my contact card", identity_box);
    copy_card_button_->setToolTip("One line of text to send to a contact so they can add you");
    auto* save_card_button = new QPushButton("Save card as file…", identity_box);
    connect(save_card_button, &QPushButton::clicked, this, [this] { save_contact_card(); });
    export_keys_button_ = new QPushButton("Export key files…", identity_box);
    export_keys_button_->setToolTip("The older way to share your public keys: two files instead of a card");
    identity_layout->addWidget(copy_card_button_);
    identity_layout->addWidget(save_card_button);
    identity_layout->addWidget(export_keys_button_);
    identity_box_layout->addLayout(identity_layout);

    auto* keys_box = new QGroupBox("Key protection", settings_dialog_);
    auto* keys_box_layout = new QVBoxLayout(keys_box);
    settings_layout_->addWidget(keys_box);
    key_status_label_ = plain_label("", keys_box);
    keys_box_layout->addWidget(key_status_label_);
    key_protection_button_ = new QPushButton("Change key protection…", keys_box);
    auto* key_menu = new QMenu(key_protection_button_);
    QAction* set_action = key_menu->addAction("Set a passphrase…");
    QAction* change_action = key_menu->addAction("Change passphrase…");
    QAction* remove_action = key_menu->addAction("Remove passphrase (less secure)…");
    key_menu->addSeparator();
    QAction* forget_action = key_menu->addAction("Forget saved passphrase");
    connect(set_action, &QAction::triggered, this, [this] { set_passphrase_action(); });
    connect(change_action, &QAction::triggered, this, [this] { change_passphrase_action(); });
    connect(remove_action, &QAction::triggered, this, [this] { remove_passphrase_action(); });
    connect(forget_action, &QAction::triggered, this, [this] { forget_saved_passphrase(); });
    connect(key_menu, &QMenu::aboutToShow, this, [this, set_action, change_action, remove_action, forget_action] {
        const bool protected_keys = keystore_->private_keys_protected();
        set_action->setEnabled(!protected_keys);
        change_action->setEnabled(protected_keys);
        remove_action->setEnabled(protected_keys);
        forget_action->setEnabled(protected_keys && keychain::available());
    });
    key_protection_button_->setMenu(key_menu);
    keys_box_layout->addWidget(key_protection_button_);

    // On the Files tab, one line about the keys, and only while they aren't protected.
    key_warning_ = new QWidget(files_page);
    key_warning_->setProperty("role", "warning-banner");
    key_warning_->setAttribute(Qt::WA_StyledBackground, true);
    auto* key_warning_layout = new QHBoxLayout(key_warning_);
    key_warning_layout->setContentsMargins(12, 6, 6, 6);
    auto* key_warning_text = plain_label("Your keys aren't protected by a passphrase: anyone who copies this computer's files could use them.", key_warning_);
    key_warning_text->setWordWrap(true);
    auto* protect_button = new QPushButton("Protect now…", key_warning_);
    protect_button->setProperty("role", "warning");
    connect(protect_button, &QPushButton::clicked, this, [this] { set_passphrase_action(); });
    key_warning_layout->addWidget(key_warning_text, 1);
    key_warning_layout->addWidget(protect_button);
    // (Shown on Home: build_home places it there.)
    update_key_status();
    layout->addSpacing(10);

    // --- The Files tab (UX step 4): two cards side by side, then what is happening, then the relay and Downloads. ---
    auto* cards = new QHBoxLayout();
    auto* send_box = new QGroupBox("Send a file", files_page);
    auto* send_layout = new QVBoxLayout(send_box);
    auto* send_text = plain_label("Encrypted so only the person you choose can open it. You'll get a link to give them.", send_box);
    send_text->setWordWrap(true);
    send_layout->addWidget(send_text);
    auto* recipient_layout = new QHBoxLayout();
    recipient_layout->addWidget(plain_label("Send to:", send_box));
    recipient_combo_ = new QComboBox(send_box);
    recipient_combo_->setMinimumWidth(150);
    recipient_layout->addWidget(recipient_combo_, 1);
    remove_contact_button_ = new QPushButton("Remove…", send_box);
    remove_contact_button_->setToolTip("Remove the selected contact and their keys");
    recipient_layout->addWidget(remove_contact_button_);
    send_layout->addLayout(recipient_layout);
    add_contact_button_ = new QPushButton("Someone new? Add a contact…", send_box);
    add_contact_button_->setProperty("role", "link");
    add_contact_button_->setToolTip("Swap contact cards with someone so you can send each other files and messages");
    send_layout->addWidget(add_contact_button_, 0, Qt::AlignLeft);
    send_layout->addStretch(1);
    send_button_ = new QPushButton("Choose file and send…", send_box);
    send_button_->setProperty("role", "primary");
    send_button_->setIcon(app_icon("upload", QColor("#ffffff")));
    send_button_->setMinimumHeight(40);
    send_layout->addWidget(send_button_);
    cards->addWidget(send_box, 1);

    auto* receive_box = new QGroupBox("Receive a file", files_page);
    auto* receive_layout = new QVBoxLayout(receive_box);
    auto* receive_text = plain_label("Paste the link someone sent you. The file is checked before it's saved to your Downloads folder.", receive_box);
    receive_text->setWordWrap(true);
    receive_layout->addWidget(receive_text);
    receive_edit_ = new QLineEdit(receive_box);
    receive_edit_->setPlaceholderText("Paste the link or transfer ID here");
    receive_layout->addWidget(receive_edit_);
    receive_layout->addStretch(1);
    receive_button_ = new QPushButton("Download", receive_box);
    receive_button_->setIcon(app_icon("download"));
    receive_button_->setMinimumHeight(40);
    receive_layout->addWidget(receive_button_);
    cards->addWidget(receive_box, 1);
    layout->addLayout(cards);
    connect(receive_edit_, &QLineEdit::returnPressed, this, [this] { receive_button_->click(); });

    // Progress and Cancel, only while a transfer runs.
    progress_row_ = new QWidget(files_page);
    auto* progress_layout = new QHBoxLayout(progress_row_);
    progress_layout->setContentsMargins(0, 0, 0, 0);
    progress_bar_ = new QProgressBar(progress_row_);
    progress_bar_->setRange(0, 100);
    progress_bar_->setValue(0);
    cancel_button_ = new QPushButton("Cancel", progress_row_);
    cancel_button_->setEnabled(false);
    progress_layout->addWidget(progress_bar_, 1);
    progress_layout->addWidget(cancel_button_);
    progress_row_->setVisible(false);
    layout->addWidget(progress_row_);

    // The link to give, once a send has one.
    result_box_ = new QGroupBox("Ready to share", files_page);
    auto* result_layout = new QVBoxLayout(result_box_);
    transfer_id_label_ = plain_label("", result_box_);
    transfer_id_label_->setWordWrap(true);
    transfer_id_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    result_layout->addWidget(transfer_id_label_);
    auto* util_layout = new QHBoxLayout();
    copy_link_button_ = new QPushButton("Copy link", result_box_);
    copy_link_button_->setProperty("role", "primary");
    copy_link_button_->setEnabled(false);
    copy_id_button_ = new QPushButton("Copy transfer ID instead", result_box_);
    copy_id_button_->setProperty("role", "link");
    copy_id_button_->setEnabled(false);
    util_layout->addWidget(copy_link_button_);
    util_layout->addWidget(copy_id_button_);
    util_layout->addStretch(1);
    result_layout->addLayout(util_layout);
    result_box_->setVisible(false);
    layout->addWidget(result_box_);

    layout->addStretch();

    // The relay (one line; Change turns it into a box), and Downloads.
    auto* footer = new QHBoxLayout();
    relay_label_ = plain_label("", files_page);
    relay_label_->setWordWrap(false);  // "Using relay host:port" fits on one line
    server_edit_ = new QLineEdit(QSettings().value(SERVER_SETTING, DEFAULT_SERVER).toString(), files_page);
    server_edit_->setPlaceholderText("host:port");
    server_edit_->setVisible(false);
    change_relay_button_ = new QPushButton("Change", files_page);
    change_relay_button_->setToolTip("The relay files are sent through");
    footer->addWidget(relay_label_);
    footer->addWidget(server_edit_, 1);
    footer->addWidget(change_relay_button_);
    footer->addStretch(1);
    open_downloads_button_ = new QPushButton("Open Downloads folder", files_page);
    footer->addWidget(open_downloads_button_);
    layout->addLayout(footer);
    connect(change_relay_button_, &QPushButton::clicked, this, [this] {
        const bool start_editing = server_edit_->isHidden();
        if (!start_editing) save_server_setting();
        server_edit_->setVisible(start_editing);
        relay_label_->setVisible(!start_editing);
        change_relay_button_->setText(start_editing ? "Done" : "Change");
        if (start_editing) server_edit_->setFocus();
    });
    connect(server_edit_, &QLineEdit::returnPressed, this, [this] { if (!server_edit_->isHidden()) change_relay_button_->click(); });
    update_relay_label();

    layout->addWidget(status_label_);

    refresh_contacts();

    // Engine callbacks run on the worker thread; marshal them to the UI thread.
    engine_.on_status = [this](const std::string& msg) {
        QMetaObject::invokeMethod(this, [this, msg]() { update_status(msg); });
    };
    engine_.on_progress = [this](double fraction) {
        QMetaObject::invokeMethod(this, [this, fraction]() { update_progress(fraction); });
    };
    engine_.on_error = [this](const std::string& error) {
        QMetaObject::invokeMethod(this, [this, error]() { show_error(error); });
    };
    engine_.on_complete = [this](const std::string& filepath) {
        QMetaObject::invokeMethod(this, [this, filepath]() { show_complete(filepath); });
    };
    engine_.on_transfer_id = [this](const std::string& id) {
        QMetaObject::invokeMethod(this, [this, id]() { show_transfer_id(id); });
    };

    connect(send_button_, &QPushButton::clicked, this, &MainWindow::start_send);
    connect(receive_button_, &QPushButton::clicked, this, &MainWindow::start_receive);
    connect(cancel_button_, &QPushButton::clicked, this, [this] {
        engine_.cancel();
        update_status("Cancelling...");
    });
    connect(add_contact_button_, &QPushButton::clicked, this, &MainWindow::add_contact);
    connect(remove_contact_button_, &QPushButton::clicked, this, &MainWindow::remove_contact);
    connect(copy_card_button_, &QPushButton::clicked, this, &MainWindow::copy_contact_card);
    connect(export_keys_button_, &QPushButton::clicked, this, &MainWindow::export_keys);
    connect(copy_link_button_, &QPushButton::clicked, this, &MainWindow::copy_share_link);
    connect(copy_id_button_, &QPushButton::clicked, this, &MainWindow::copy_transfer_id);
    connect(open_downloads_button_, &QPushButton::clicked, this, &MainWindow::open_downloads);
    connect(server_edit_, &QLineEdit::editingFinished, this, &MainWindow::save_server_setting);

    // The Chats tab owns the messaging engine and its worker thread.
    chat_widget_ = new ChatWidget(*keystore_, keystore_->app_dir() / "history.db", tabs);
    const int chats_tab = tabs->addTab(chat_widget_, "Chats");

    // Settings, reachable from either tab; its messaging part works through the Chats tab's own actions.
    auto* settings_button = new QPushButton("Settings…", tabs);
    settings_button->setIcon(app_icon("settings"));
    settings_button->setToolTip("Your fingerprint and contact card, key protection, relay invites, issued cards, restoring history");
    tabs->setCornerWidget(settings_button, Qt::TopRightCorner);
    connect(settings_button, &QPushButton::clicked, this, [this] { open_settings(); });
    auto* messaging_box = new QGroupBox("Messaging", settings_dialog_);
    auto* messaging_box_layout = new QVBoxLayout(messaging_box);
    settings_messaging_status_ = plain_label("", messaging_box);
    settings_messaging_status_->setWordWrap(true);
    messaging_box_layout->addWidget(settings_messaging_status_);
    auto* messaging_buttons = new QHBoxLayout();
    settings_setup_button_ = new QPushButton("Set up messaging…", messaging_box);
    settings_invites_button_ = new QPushButton("Relay invites…", messaging_box);
    settings_invites_button_->setToolTip("Make a one-time invite so a friend can use this relay (you are vouching for them)");
    settings_cards_button_ = new QPushButton("Cards issued…", messaging_box);
    settings_cards_button_->setToolTip("Every contact card you've handed out, whether it's been used, and by whom");
    settings_restore_button_ = new QPushButton("Restore history…", messaging_box);
    settings_restore_button_->setToolTip("After reinstalling: get your saved chats back from the relay");
    for (QPushButton* b : {settings_setup_button_, settings_invites_button_, settings_cards_button_, settings_restore_button_}) messaging_buttons->addWidget(b);
    messaging_buttons->addStretch(1);
    messaging_box_layout->addLayout(messaging_buttons);
    settings_layout_->addWidget(messaging_box);
    // Each opens its own window: Settings closes first, so the two never stack up.
    connect(settings_setup_button_, &QPushButton::clicked, this, [this] { settings_dialog_->accept(); chat_widget_->open_setup(); });
    connect(settings_invites_button_, &QPushButton::clicked, this, [this] { settings_dialog_->accept(); chat_widget_->open_relay_invites(); });
    connect(settings_cards_button_, &QPushButton::clicked, this, [this] { settings_dialog_->accept(); chat_widget_->open_cards_issued(); });
    connect(settings_restore_button_, &QPushButton::clicked, this, [this] { settings_dialog_->accept(); chat_widget_->open_restore(); });
    auto* close_row = new QHBoxLayout();
    close_row->addStretch(1);
    auto* close_button = new QPushButton("Close", settings_dialog_);
    close_button->setDefault(true);
    connect(close_button, &QPushButton::clicked, settings_dialog_, &QDialog::accept);
    close_row->addWidget(close_button);
    settings_layout_->addLayout(close_row);
    // Setting up messaging on a relay also sets the Files tab's relay to it.
    chat_widget_->set_on_add_contact([this] { add_contact(); });
    chat_widget_->set_on_relay_chosen([this](const QString& server) {
        server_edit_->setText(server);
        save_server_setting();
    });
    // Something arrived while another tab was showing: say so on the Chats tab.
    (void)chats_tab;  // tabs move (Home comes first), so the Chats tab is looked up each time
    chat_widget_->set_on_unread_changed([this](size_t unread) {
        tabs_->setTabText(tabs_->indexOf(chat_widget_), unread ? QString("Chats (%1)").arg(static_cast<qulonglong>(unread)) : QString("Chats"));
    });
    connect(tabs, &QTabWidget::currentChanged, this, [this](int) {
        chat_widget_->refresh_now();
        refresh_home();
    });
    build_home();
    chat_widget_->set_on_changed([this] { refresh_home(); });
    // What a new user chose in the first-run guide, now that the window (and the Chats tab) exist.
    if (!pending_invite_.isEmpty() || pending_add_contact_) {
        QTimer::singleShot(0, this, [this] {
            const QString invite = pending_invite_;
            pending_invite_.clear();
            if (!invite.isEmpty()) chat_widget_->setup_with_invite(invite);
            if (pending_add_contact_) {
                pending_add_contact_ = false;
                add_contact();
            }
        });
    }  // shown again: what was waiting is seen
}

MainWindow::~MainWindow() {
    // The Chats tab's worker thread uses the key store. Qt would delete the tab only after this
    // window's members (including the key store) are gone, so stop and delete it here, first.
    if (chat_widget_) {
        delete chat_widget_;
        chat_widget_ = nullptr;
    }
    engine_.cancel();
    if (worker_thread_.joinable()) worker_thread_.join();
    if (keystore_) keystore_->lock();  // wipe the decrypted keys from memory
}

// --- Key protection ---

std::string MainWindow::keychain_account() const {
    // One entry per identity, so several key folders on one computer don't collide.
    return "key-passphrase-" + keystore_->own_fingerprint().substr(0, 16);
}

void MainWindow::remember_passphrase(const std::string& passphrase) {
    if (!keychain::store(keychain_account(), passphrase)) {
        QMessageBox::warning(this, "Keychain",
                             "The passphrase could not be saved to your system's keychain (is a keyring "
                             "service running?). Your keys are still protected; you will be asked for the "
                             "passphrase each time you start the app.");
    }
}

// Runs before the window is shown: creates, validates and (if needed) unlocks the keys.
// The first-run guide: five steps in one window, each checked before moving on. Closing it before the end cancels set-up.
bool MainWindow::run_first_run_guide(FirstRunChoices& out) {
    QDialog dialog(this);
    dialog.setWindowTitle("Welcome to PQ File Transfer");
    dialog.setMinimumWidth(580);
    auto* layout = new QVBoxLayout(&dialog);
    auto* step_label = plain_label("", &dialog);
    layout->addWidget(step_label);
    auto* pages = new QStackedWidget(&dialog);
    layout->addWidget(pages, 1);
    auto page = [&](const QString& title, const QString& text) {
        auto* w = new QWidget(pages);
        auto* l = new QVBoxLayout(w);
        auto* t = plain_label(title, w);
        t->setStyleSheet("font-size: 18px; font-weight: bold;");
        l->addWidget(t);
        auto* body = plain_label(text, w);
        body->setWordWrap(true);
        l->addWidget(body);
        pages->addWidget(w);
        return l;
    };

    auto* welcome = page("Welcome", "Send files and messages that only the people you choose can read, protected by post-quantum "
                                    "encryption.\n\nSetting up takes about a minute: your name, a passphrase for your keys, and, if "
                                    "you have one, an invite for messaging.");
    welcome->addStretch(1);

    auto* name_page = page("Your name", "The name your contacts see on your contact card. You can change it whenever you make a new card.");
    auto* name_edit = new QLineEdit(QSettings().value("display_name", default_display_name()).toString(), &dialog);
    name_edit->setPlaceholderText("Your name");
    name_page->addWidget(name_edit);
    name_page->addStretch(1);

    auto* protect_page = page("Protect your keys", "Your keys are what make your messages and files yours. A passphrase keeps them useless to "
                                                   "anyone who copies this computer's files. It can't be recovered if you forget it.");
    auto* protect_yes = new QRadioButton("Protect them with a passphrase (recommended)", &dialog);
    auto* protect_no = new QRadioButton("Not now (you can do this later in Settings)", &dialog);
    protect_yes->setChecked(true);
    protect_page->addWidget(protect_yes);
    protect_page->addWidget(protect_no);
    protect_page->addStretch(1);

    auto* connect_page = page("Connect for messaging", "Chats go through a relay: a server that passes on encrypted messages it can't read. "
                                                       "Whoever runs one can give you an invite.");
    auto* invite_yes = new QRadioButton("I have an invite", &dialog);
    auto* invite_edit = new QLineEdit(&dialog);
    invite_edit->setPlaceholderText("Paste it here: pqft-relay://…");
    auto* invite_no = new QRadioButton("Not now: I'll just send files (you can set up messaging any time from Home)", &dialog);
    invite_no->setChecked(true);
    connect_page->addWidget(invite_yes);
    connect_page->addWidget(invite_edit);
    connect_page->addWidget(invite_no);
    connect_page->addStretch(1);
    connect(invite_edit, &QLineEdit::textEdited, &dialog, [invite_yes] { invite_yes->setChecked(true); });

    auto* done_page = page("You're all set", "Next, add your first contact: you each share your contact card once, and check each "
                                             "other's fingerprint. You'll find everything else on Home.");
    done_page->addStretch(1);

    auto* buttons = new QHBoxLayout();
    auto* back = new QPushButton("Back", &dialog);
    auto* next = new QPushButton("Get started", &dialog);
    next->setProperty("role", "primary");
    auto* go_home = new QPushButton("Go to Home", &dialog);
    auto* add_first = new QPushButton("Add your first contact", &dialog);
    add_first->setProperty("role", "primary");
    next->setDefault(true);
    buttons->addWidget(back);
    buttons->addStretch(1);
    buttons->addWidget(go_home);
    buttons->addWidget(add_first);
    buttons->addWidget(next);
    layout->addLayout(buttons);

    const int last = pages->count() - 1;
    auto show_step = [=](int index) {
        pages->setCurrentIndex(index);
        step_label->setText(QString("Step %1 of %2").arg(static_cast<qulonglong>(index + 1)).arg(static_cast<qulonglong>(last + 1)));
        back->setEnabled(index > 0);
        next->setText(index == 0 ? "Get started" : "Next");
        next->setVisible(index < last);
        go_home->setVisible(index == last);
        add_first->setVisible(index == last);
        if (index == last) add_first->setDefault(true);
        else next->setDefault(true);
    };
    connect(back, &QPushButton::clicked, &dialog, [=] { show_step(std::max(0, pages->currentIndex() - 1)); });
    connect(next, &QPushButton::clicked, &dialog, [&, show_step] {
        const int index = pages->currentIndex();
        if (index == 1) {  // the name
            const QString name = name_edit->text().trimmed();
            if (name.isEmpty() || name.toUtf8().size() > 64) {
                QMessageBox::warning(&dialog, "Your name", "Please enter a name of up to 64 bytes.");
                return;
            }
            out.name = name;
        } else if (index == 2) {  // key protection: the usual passphrase window, asked here
            out.protect = protect_yes->isChecked();
            std::fill(out.passphrase.begin(), out.passphrase.end(), '\0');
            out.passphrase.clear();
            if (out.protect) {
                auto choice = ask_new_passphrase(&dialog, "Choose a passphrase", protection_explanation("Choose a passphrase for your keys."), false);
                if (choice.outcome != DialogOutcome::Accepted) return;  // stay on this step
                out.passphrase = choice.passphrase;
                out.remember = choice.remember;
                std::fill(choice.passphrase.begin(), choice.passphrase.end(), '\0');
            }
        } else if (index == 3) {  // the invite, checked now and used once the window is open
            out.invite.clear();
            if (invite_yes->isChecked()) {
                const QString text = invite_edit->text().trimmed();
                if (!parse_relay_invite(text.toStdString())) {
                    QMessageBox::warning(&dialog, "Connect for messaging",
                                         "That invite isn't valid. Paste it exactly as you were given it, or choose \"Not now\".");
                    return;
                }
                out.invite = text;
            }
        }
        show_step(index + 1);
    });
    connect(go_home, &QPushButton::clicked, &dialog, [&] {
        out.add_contact = false;
        dialog.accept();
    });
    connect(add_first, &QPushButton::clicked, &dialog, [&] {
        out.add_contact = true;
        dialog.accept();
    });
    show_step(0);
    const bool finished = dialog.exec() == QDialog::Accepted;
    if (!finished) {
        std::fill(out.passphrase.begin(), out.passphrase.end(), '\0');
        out.passphrase.clear();
    }
    return finished;
}

bool MainWindow::setup_keys(std::string& problem) {
    QSettings settings;

    if (!keystore_->keys_exist()) {
        // A new user: the first-run guide (UX step 6). The keys are made with its passphrase choice; its invite and
        // "add your first contact" are acted on once the window exists.
        FirstRunChoices choices;
        if (!run_first_run_guide(choices)) {
            problem = "Setup was cancelled. Restart the app to set up your keys.";
            return false;
        }
        keystore_->initialize_keys(choices.protect ? choices.passphrase : std::string());
        settings.setValue(KEY_PROTECTION_DECIDED, true);
        if (choices.protect && choices.remember) remember_passphrase(choices.passphrase);
        std::fill(choices.passphrase.begin(), choices.passphrase.end(), '\0');
        settings.setValue("display_name", choices.name);
        pending_invite_ = choices.invite;
        pending_add_contact_ = choices.add_contact;
        return true;
    }

    keystore_->initialize_keys();  // validates the existing keys
    if (keystore_->private_keys_locked()) return unlock_keys(problem);

    // Keys from an earlier version are unprotected. Offer protection once; respect a "skip".
    if (!keystore_->private_keys_protected() && !settings.value(KEY_PROTECTION_DECIDED, false).toBool()) {
        auto choice = ask_new_passphrase(
            this, "Protect your keys?",
            protection_explanation("Your keys are currently stored on this computer without a passphrase. "
                                   "Protecting them doesn't change your fingerprint, so your contacts "
                                   "don't need to do anything."),
            true);
        if (choice.outcome == DialogOutcome::Accepted) {
            try {
                keystore_->set_passphrase(choice.passphrase);
            } catch (const std::exception& e) {
                QMessageBox::warning(this, "Key Protection", qstr(e.what()));
                return true;  // keys still work, just unprotected; ask again next time
            }
            settings.setValue(KEY_PROTECTION_DECIDED, true);
            if (choice.remember) remember_passphrase(choice.passphrase);
        } else if (choice.outcome == DialogOutcome::Skipped) {
            settings.setValue(KEY_PROTECTION_DECIDED, true);  // their choice; don't nag
        }
        // Cancelled (window closed): carry on unprotected and ask again next start.
    }
    return true;
}

bool MainWindow::unlock_keys(std::string& problem) {
    const std::string account = keychain_account();

    // The keychain first: this is what makes unlocking invisible on a normal day.
    if (auto saved = keychain::load(account)) {
        try {
            if (keystore_->unlock(*saved)) return true;
        } catch (const std::exception& e) {
            problem = e.what();
            return false;
        }
        keychain::remove(account);  // stale (e.g. the keys were replaced); fall through to asking
    }

    QString message = "Enter your passphrase to unlock your keys.";
    while (true) {
        auto choice = ask_existing_passphrase(this, "Unlock your keys", message, true);
        if (choice.outcome != DialogOutcome::Accepted) {
            problem = "Your keys are locked. Restart the app and enter your passphrase to continue.";
            return false;
        }
        try {
            if (keystore_->unlock(choice.passphrase)) {
                if (choice.remember) remember_passphrase(choice.passphrase);
                return true;
            }
        } catch (const std::exception& e) {
            problem = e.what();
            return false;
        }
        message = "That passphrase is wrong. Try again.";
    }
}

// Home (UX step 5): where the app opens. What's going on, anything waiting, the four things people come to do, and recent chats.
void MainWindow::build_home() {
    home_page_ = new QWidget(tabs_);
    auto* layout = new QVBoxLayout(home_page_);

    auto* status_row = new QHBoxLayout();
    home_status_ = plain_label("", home_page_);
    home_status_->setWordWrap(true);
    home_setup_button_ = new QPushButton("Set up messaging…", home_page_);
    connect(home_setup_button_, &QPushButton::clicked, this, [this] { chat_widget_->open_setup(); });
    status_row->addWidget(home_status_, 1);
    status_row->addWidget(home_setup_button_);
    layout->addLayout(status_row);

    if (key_warning_) layout->addWidget(key_warning_);  // only while the keys aren't protected (update_key_status)

    home_waiting_ = new QWidget(home_page_);
    home_waiting_->setProperty("role", "info-banner");
    home_waiting_->setAttribute(Qt::WA_StyledBackground, true);
    auto* waiting_layout = new QHBoxLayout(home_waiting_);
    waiting_layout->setContentsMargins(12, 6, 6, 6);
    home_waiting_text_ = plain_label("", home_waiting_);
    auto* review = new QPushButton("Review", home_waiting_);
    connect(review, &QPushButton::clicked, this, [this] { tabs_->setCurrentWidget(chat_widget_); });
    waiting_layout->addWidget(home_waiting_text_, 1);
    waiting_layout->addWidget(review);
    home_waiting_->setVisible(false);
    layout->addWidget(home_waiting_);

    // Four tiles of equal width: an icon, a bold title, and a muted line saying what it's for. The labels let clicks through
    // to the tile, which is a real button (keyboard focus, Enter, Space).
    auto* actions = new QHBoxLayout();
    auto big = [this, actions](const QString& icon, const QString& title, const QString& text, bool primary, QLabel** text_label) {
        auto* b = new QPushButton(home_page_);
        b->setProperty("role", primary ? "tile-primary" : "tile");
        b->setMinimumHeight(118);
        b->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);  // equal widths, whatever the text
        b->setAccessibleName(title);
        b->setToolTip(text);
        auto* inner = new QVBoxLayout(b);
        inner->setContentsMargins(16, 14, 16, 14);
        inner->setSpacing(4);
        const QPixmap pixmap = app_icon_pixmap(icon, 26, primary ? QColor("#ffffff") : QColor("#ececee"));
        if (!pixmap.isNull()) {
            auto* picture = new QLabel(b);
            picture->setPixmap(pixmap);
            picture->setAttribute(Qt::WA_TransparentForMouseEvents);
            inner->addWidget(picture);
        }
        inner->addStretch(1);
        auto* t = plain_label(title, b);
        t->setProperty("role", "tile-title");
        t->setAttribute(Qt::WA_TransparentForMouseEvents);
        inner->addWidget(t);
        auto* d = plain_label(text, b);
        d->setProperty("role", "tile-text");
        d->setAttribute(Qt::WA_TransparentForMouseEvents);
        inner->addWidget(d);
        if (text_label) *text_label = d;
        actions->addWidget(b, 1);
        return b;
    };
    home_chats_button_ = big("chat", "Open chats", "Nothing new", true, &home_chats_text_);
    auto* add = big("user-plus", "Add contact", "Swap contact cards with someone", false, nullptr);
    auto* send = big("upload", "Send a file", "Encrypted for one person", false, nullptr);
    auto* receive = big("download", "Receive a file", "Paste the link you were sent", false, nullptr);
    connect(home_chats_button_, &QPushButton::clicked, this, [this] { tabs_->setCurrentWidget(chat_widget_); });
    connect(add, &QPushButton::clicked, this, [this] { add_contact(); });
    connect(send, &QPushButton::clicked, this, [this] {
        tabs_->setCurrentWidget(files_page_);
        recipient_combo_->setFocus();
    });
    connect(receive, &QPushButton::clicked, this, [this] {
        tabs_->setCurrentWidget(files_page_);
        receive_edit_->setFocus();
    });
    layout->addLayout(actions);

    auto* recent_heading = plain_label("Recent chats", home_page_);
    recent_heading->setProperty("role", "section");
    layout->addWidget(recent_heading);
    home_recent_ = new QListWidget(home_page_);
    home_recent_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    connect(home_recent_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) {
        if (!item) return;
        chat_widget_->open_conversation(item->data(Qt::UserRole).toString());
        tabs_->setCurrentWidget(chat_widget_);
    });
    connect(home_recent_, &QListWidget::itemClicked, this, [this](QListWidgetItem* item) {
        if (!item) return;
        chat_widget_->open_conversation(item->data(Qt::UserRole).toString());
        tabs_->setCurrentWidget(chat_widget_);
    });
    layout->addWidget(home_recent_);
    home_recent_empty_ = plain_label("No chats yet. Use Add contact to swap contact cards with someone, and your chats will appear here.", home_page_);
    home_recent_empty_->setWordWrap(true);
    layout->addWidget(home_recent_empty_);
    layout->addStretch();

    // Home first, then Chats, then Files; the app opens on Home.
    tabs_->insertTab(0, home_page_, "Home");
    tabs_->tabBar()->moveTab(tabs_->indexOf(chat_widget_), 1);
    tabs_->setCurrentWidget(home_page_);
    refresh_home();
}

void MainWindow::refresh_home() {
    if (!home_page_ || !chat_widget_) return;
    const bool set_up = chat_widget_->is_set_up();
    const QString status = chat_widget_->messaging_status();
    const QString waiting = chat_widget_->waiting_summary();
    const size_t unread = chat_widget_->unread_total();
    const auto recent = chat_widget_->recent_entries(5);
    QString signature = status + "|" + waiting + "|" + QString::number(static_cast<qulonglong>(unread)) + (set_up ? "|1" : "|0");
    for (const auto& r : recent) signature += "|" + r.key + "=" + r.title + "/" + r.subtitle + "/" + QString::number(static_cast<qulonglong>(r.unread)) + "/" + QString::number(static_cast<qlonglong>(r.when));
    if (signature == home_signature_) return;  // nothing changed: leave it alone
    home_signature_ = signature;
    home_status_->setText(set_up ? "Messaging: " + status : QString("Messaging isn't set up yet. Set it up to chat with your contacts (you'll need an invite from a relay)."));
    home_setup_button_->setVisible(!set_up);
    home_waiting_text_->setText("Waiting for you: " + waiting);
    home_waiting_->setVisible(!waiting.isEmpty());
    home_chats_text_->setText(unread ? QString("%1 unread").arg(static_cast<qulonglong>(unread)) : QString("Nothing new"));
    fill_chat_list(home_recent_, recent);
    home_recent_->setFixedHeight(static_cast<int>(recent.size()) * 62 + 12);  // as tall as its chats, no taller
    home_recent_->setVisible(!recent.empty());
    home_recent_empty_->setVisible(recent.empty());
}

void MainWindow::open_settings() {
    if (!settings_dialog_) return;
    const bool set_up = chat_widget_ && chat_widget_->is_set_up();
    if (settings_messaging_status_) settings_messaging_status_->setText(chat_widget_ ? chat_widget_->messaging_status() : QString());
    if (settings_setup_button_) settings_setup_button_->setVisible(!set_up);
    for (QPushButton* b : {settings_invites_button_, settings_cards_button_, settings_restore_button_})
        if (b) b->setEnabled(set_up);
    update_key_status();
    settings_dialog_->exec();
}

void MainWindow::update_key_status() {
    if (keystore_->private_keys_protected()) {
        key_status_label_->setText("Your keys are protected by a passphrase.");
        key_status_label_->setStyleSheet(QString("color: ") + app_colors::success + ";");
    } else {
        key_status_label_->setText("Your keys aren't protected by a passphrase.");
        key_status_label_->setStyleSheet(QString("color: ") + app_colors::warning + ";");
    }
    if (key_warning_) key_warning_->setVisible(!keystore_->private_keys_protected());
}

void MainWindow::set_passphrase_action() {
    auto choice = ask_new_passphrase(this, "Set a passphrase",
                                     protection_explanation("Protect your keys with a passphrase."), false);
    if (choice.outcome != DialogOutcome::Accepted) return;
    try {
        keystore_->set_passphrase(choice.passphrase);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Key Protection", qstr(e.what()));
        return;
    }
    QSettings().setValue(KEY_PROTECTION_DECIDED, true);
    if (choice.remember) remember_passphrase(choice.passphrase);
    update_key_status();
    update_status("Your keys are now protected by a passphrase");
}

void MainWindow::change_passphrase_action() {
    auto current = ask_existing_passphrase(this, "Change passphrase", "Enter your current passphrase.", false, "Continue");
    if (current.outcome != DialogOutcome::Accepted) return;
    if (!keystore_->verify_passphrase(current.passphrase)) {
        QMessageBox::warning(this, "Change passphrase", "That passphrase is wrong.");
        return;
    }
    auto fresh = ask_new_passphrase(this, "Change passphrase", "Choose a new passphrase.", false);
    if (fresh.outcome != DialogOutcome::Accepted) return;
    try {
        keystore_->set_passphrase(fresh.passphrase);
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Key Protection", qstr(e.what()));
        return;
    }
    if (keychain::available()) {
        if (fresh.remember) remember_passphrase(fresh.passphrase);
        else keychain::remove(keychain_account());
    }
    update_key_status();
    update_status("Passphrase changed");
}

void MainWindow::remove_passphrase_action() {
    QMessageBox warn(QMessageBox::Warning, "Remove passphrase",
                     "Your private keys will be stored on this computer without protection. Anyone who "
                     "can copy your key files, for example from a stolen laptop or a backup, will be able "
                     "to read files sent to you.\n\nRemove the passphrase anyway?",
                     QMessageBox::Yes | QMessageBox::No, this);
    warn.setTextFormat(Qt::PlainText);
    warn.setDefaultButton(QMessageBox::No);
    if (warn.exec() != QMessageBox::Yes) return;

    auto current = ask_existing_passphrase(this, "Remove passphrase", "Enter your current passphrase to confirm.",
                                           false, "Remove");
    if (current.outcome != DialogOutcome::Accepted) return;
    if (!keystore_->verify_passphrase(current.passphrase)) {
        QMessageBox::warning(this, "Remove passphrase", "That passphrase is wrong.");
        return;
    }
    try {
        keystore_->remove_passphrase();
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Key Protection", qstr(e.what()));
        return;
    }
    keychain::remove(keychain_account());
    QSettings().setValue(KEY_PROTECTION_DECIDED, true);
    update_key_status();
    update_status("The passphrase was removed. Your keys are stored without protection");
}

void MainWindow::forget_saved_passphrase() {
    keychain::remove(keychain_account());
    update_status("Saved passphrase removed. You will be asked for it next time you start the app");
}

// --- Contacts ---

void MainWindow::refresh_contacts() {
    QString previous = recipient_combo_->currentData().toString();
    recipient_combo_->clear();

    // Item data holds the contact name; an empty string means "send to myself".
    recipient_combo_->addItem("Myself (test)", QString());

    for (const auto& name : keystore_->list_contacts()) {
        auto contact = keystore_->load_contact(name);
        QString label = qstr(name);
        if (!contact) label += " (invalid keys)";
        else if (!contact->kem_verified) label += " (key not verified)";
        recipient_combo_->addItem(label, qstr(name));
        if (contact) {
            QString tip = "Fingerprint:\n" + formatted_fingerprint(contact->fingerprint);
            if (!contact->kem_verified)
                tip += "\n\nTheir encryption key is not verified. Ask them to send a new contact card "
                       "from the latest version.";
            recipient_combo_->setItemData(recipient_combo_->count() - 1, tip, Qt::ToolTipRole);
        }
    }

    int idx = recipient_combo_->findData(previous);
    if (idx >= 0) recipient_combo_->setCurrentIndex(idx);
    if (chat_widget_) chat_widget_->refresh();
}

// The Add a contact dialog: both halves of swapping cards in one place. Share your card (copy it, or save it as a file), and
// add theirs (paste it, optionally name them). Adding runs the same checks as always, ending with the fingerprint check; if
// anything is wrong with what was pasted, the dialog stays open so it can be corrected.
void MainWindow::add_contact() {
    QDialog dialog(this);
    dialog.setWindowTitle("Add a contact");
    dialog.setMinimumWidth(560);
    auto* layout = new QVBoxLayout(&dialog);

    auto* intro = plain_label("To message each other, you both share your contact card once: send yours to them, and add theirs here.", &dialog);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto* share = new QGroupBox("1 · Share your card", &dialog);
    auto* share_layout = new QVBoxLayout(share);
    auto* share_buttons = new QHBoxLayout();
    auto* copy_button = new QPushButton("Copy my card", share);
    copy_button->setProperty("role", "primary");
    auto* save_button = new QPushButton("Save as file…", share);
    share_buttons->addWidget(copy_button);
    share_buttons->addWidget(save_button);
    share_buttons->addStretch(1);
    share_layout->addLayout(share_buttons);
    auto* share_note = plain_label("Send it any way you like: email, another chat app, a USB stick. It holds no secrets.", share);
    share_note->setWordWrap(true);
    share_layout->addWidget(share_note);
    layout->addWidget(share);

    auto* theirs = new QGroupBox("2 · Add their card", &dialog);
    auto* theirs_layout = new QVBoxLayout(theirs);
    theirs_layout->addWidget(plain_label("Their card", theirs));
    auto* card_edit = new QPlainTextEdit(theirs);
    card_edit->setPlaceholderText("Paste the card they sent you");
    card_edit->setTabChangesFocus(true);
    card_edit->setFixedHeight(90);
    theirs_layout->addWidget(card_edit);
    theirs_layout->addWidget(plain_label("Name them (optional: their card suggests a name)", theirs));
    auto* name_edit = new QLineEdit(theirs);
    name_edit->setPlaceholderText("How they'll appear in your contacts");
    theirs_layout->addWidget(name_edit);
    layout->addWidget(theirs);

    auto* check_note = plain_label("Before they're added you'll see their fingerprint: check it with them in person or on a call, so you "
                                   "know nobody swapped the card on the way.", &dialog);
    check_note->setWordWrap(true);
    layout->addWidget(check_note);

    auto* footer = new QHBoxLayout();
    auto* files_button = new QPushButton("Use key files instead…", &dialog);
    files_button->setToolTip("For contacts who sent you their two public key files rather than a card");
    files_button->setProperty("role", "link");
    auto* cancel_button = new QPushButton("Cancel", &dialog);
    auto* add_button = new QPushButton("Add contact", &dialog);
    add_button->setProperty("role", "primary");
    add_button->setDefault(true);
    add_button->setEnabled(false);
    footer->addWidget(files_button);
    footer->addStretch(1);
    footer->addWidget(cancel_button);
    footer->addWidget(add_button);
    layout->addLayout(footer);

    bool use_files = false;
    connect(copy_button, &QPushButton::clicked, &dialog, [this] { copy_contact_card(); });
    connect(save_button, &QPushButton::clicked, &dialog, [this] { save_contact_card(); });
    connect(card_edit, &QPlainTextEdit::textChanged, &dialog, [card_edit, add_button] { add_button->setEnabled(!card_edit->toPlainText().trimmed().isEmpty()); });
    connect(cancel_button, &QPushButton::clicked, &dialog, &QDialog::reject);
    connect(files_button, &QPushButton::clicked, &dialog, [&dialog, &use_files] {
        use_files = true;
        dialog.reject();
    });
    connect(add_button, &QPushButton::clicked, &dialog, [this, &dialog, card_edit, name_edit] {
        if (add_contact_from_card_text(card_edit->toPlainText(), name_edit->text().trimmed())) dialog.accept();
    });
    dialog.exec();
    if (use_files) add_contact_from_files();
}

// Asks for a contact name, validates it, and confirms before replacing an existing contact.
std::optional<QString> MainWindow::ask_contact_name(const QString& suggested) {
    bool ok = false;
    QString name = QInputDialog::getText(this, "Add Contact",
                                         "Contact name (letters, digits, spaces, - _ .):",
                                         QLineEdit::Normal, suggested, &ok).trimmed();
    if (!ok || name.isEmpty()) return std::nullopt;
    if (!confirm_contact_name(name)) return std::nullopt;
    return name;
}

bool MainWindow::confirm_contact_name(const QString& name) {
    std::string name_str = name.toStdString();
    if (!KeyStore::is_valid_contact_name(name_str)) {
        QMessageBox::warning(this, "Add Contact",
                             "Please use 1-64 letters, digits, spaces, '-', '_' or '.'. "
                             "The name can't start or end with a dot or space, or be \"self\".");
        return false;
    }
    if (keystore_->contact_exists(name_str) &&
        QMessageBox::question(this, "Add Contact",
                              "A contact named \"" + name + "\" already exists.\n\n"
                              "If the keys you are adding differ from the saved ones, that is a key change: " + name +
                              " has a new identity, or this is someone else's card. You must check the new "
                              "fingerprint with them again before trusting it.\n\nReplace the saved keys?") !=
            QMessageBox::Yes) {
        return false;
    }
    return true;
}

bool MainWindow::add_contact_from_card_text(const QString& text, const QString& chosen_name) {
    // The box starts empty: the user pastes the card themselves (nothing is read from the clipboard unasked).
    if (text.trimmed().isEmpty()) return false;
    std::string error;
    auto card = decode_any_contact_card(text.trimmed().toStdString(), &error);
    if (!card) {
        QMessageBox::warning(this, "Add Contact", qstr(error));
        return false;
    }

    if (card->bundle) {
        // A card from someone you already have is an update. Only the owner of the signing key
        // can make a valid newer one, so it is applied without asking.
        auto outcome = keystore_->import_bundle_for_known_identity(*card->bundle, card->send_token);
        using Result = KeyStore::BundleImportResult;
        if (outcome.result != Result::UnknownIdentity) {
            refresh_contacts();
            const QString who = qstr(outcome.contact_name);
            if (outcome.result == Result::Updated) {
                QString msg = "Updated " + who + "'s contact card.";
                if (outcome.was_unverified) msg += " Their encryption key is now verified.";
                if (card->bundle && card->bundle->has_mailbox() && !card->send_token.empty()) msg += " You can message them.";
                update_status(msg.toStdString());
                if (outcome.was_unverified && outcome.encryption_key_changed) {
                    QMessageBox warn(QMessageBox::Warning, "Encryption key replaced",
                                     "The encryption key you had saved for " + who + " did not match the key in "
                                     "their signed card, so it was replaced with the signed one.\n\nThe earlier "
                                     "card may have been altered on its way to you. If so, files you sent them "
                                     "before now could have been readable by someone else.",
                                     QMessageBox::Ok, this);
                    warn.setTextFormat(Qt::PlainText);
                    warn.exec();
                }
            } else if (outcome.result == Result::Unchanged) {
                update_status("You already have this contact card for " + who.toStdString());
            } else {
                QMessageBox::warning(this, "Add Contact",
                                     "This card for " + who + " is older than the one you have, and uses a "
                                     "different encryption key. It was ignored.");
                return false;
            }
            return true;
        }
    } else {
        QMessageBox old_card(QMessageBox::Warning, "Older contact card",
                             "This card comes from an older version of the app. It cannot prove that the "
                             "encryption key belongs to the person: someone who altered it on the way could "
                             "read the files you send, even if the fingerprint matches.\n\nAsk the sender to "
                             "update the app and send a new card. You can add them now, and they will be marked "
                             "\"encryption key not verified\" until you do.\n\nAdd them anyway?",
                             QMessageBox::Yes | QMessageBox::No, this);
        old_card.setTextFormat(Qt::PlainText);
        old_card.setDefaultButton(QMessageBox::No);
        if (old_card.exec() != QMessageBox::Yes) return false;
    }

    std::optional<QString> name;
    if (!chosen_name.isEmpty()) {
        if (confirm_contact_name(chosen_name)) name = chosen_name;
    } else {
        name = ask_contact_name(qstr(sanitize_contact_name(card->name)));
    }
    if (!name) return false;
    return finish_add_contact(*name, card->pub_kem, card->pub_dsa, card->server, card->bundle ? &*card->bundle : nullptr,
                              card->send_token);
}

void MainWindow::add_contact_from_files() {
    auto name = ask_contact_name(QString());
    if (!name) return;

    QString kem_path = QFileDialog::getOpenFileName(this, "Select " + *name + "'s ML-KEM public key (pq_public_kem.key)");
    if (kem_path.isEmpty()) return;
    QString dsa_path = QFileDialog::getOpenFileName(this, "Select " + *name + "'s ML-DSA public key (pq_public_dsa.key)");
    if (dsa_path.isEmpty()) return;

    auto pub_kem = read_small_file(kem_path, 64 * 1024);
    auto pub_dsa = read_small_file(dsa_path, 64 * 1024);
    const size_t kem_size = CryptoEngine::kem_public_key_size();
    const size_t dsa_size = CryptoEngine::sig_public_key_size();

    // The two key types have different sizes, so a swapped selection is fixable.
    if (pub_kem.size() == dsa_size && pub_dsa.size() == kem_size) std::swap(pub_kem, pub_dsa);
    if (pub_kem.size() != kem_size || pub_dsa.size() != dsa_size) {
        QMessageBox::warning(this, "Add Contact",
                             QString("Those files don't look like PQ File Transfer public keys "
                                     "(expected %1 and %2 bytes).").arg(static_cast<qulonglong>(kem_size)).arg(static_cast<qulonglong>(dsa_size)));
        return;
    }
    finish_add_contact(*name, pub_kem, pub_dsa, std::string(), nullptr);
}

// Shared by both ways of adding a contact: sanity checks, fingerprint confirmation, save.
bool MainWindow::finish_add_contact(const QString& name,
                                    const std::vector<uint8_t>& pub_kem,
                                    const std::vector<uint8_t>& pub_dsa,
                                    const std::string& card_server,
                                    const IdentityBundle* bundle,
                                    const std::vector<uint8_t>& send_token) {
    std::string name_str = name.toStdString();
    std::string fp = CryptoEngine::fingerprint(pub_dsa);
    if (fp == keystore_->own_fingerprint()) {
        QMessageBox::warning(this, "Add Contact", "These are your own public keys.");
        return false;
    }
    if (auto existing = keystore_->find_contact_by_fingerprint(fp); existing && existing->name != name_str) {
        QMessageBox::warning(this, "Add Contact",
                             "These keys are already saved as \"" + qstr(existing->name) + "\".");
        return false;
    }

    const QString risk = bundle
        ? "This card is signed, so its keys can't be altered on the way without being noticed. A signature "
          "can't say who made the card, though. If someone else made it, they could read the files you send "
          "and pretend to be " + name + "."
        : "A contact card or key files can be swapped on the way to you. If that happened, the sender could "
          "read the files you send and pretend to be " + name + ". This one has no signature on its encryption "
          "key, so it will be marked \"encryption key not verified\".";
    QMessageBox confirm(QMessageBox::Question, "Verify Fingerprint",
                        "Before trusting these keys, confirm with " + name +
                        " over a channel you trust (in person, or a phone or video call where you "
                        "recognise them) that their fingerprint is:\n\n" + formatted_fingerprint(fp) +
                        "\n\n" + risk + "\n\nDoes the fingerprint match?",
                        QMessageBox::Yes | QMessageBox::No, this);
    confirm.setTextFormat(Qt::PlainText);
    if (confirm.exec() != QMessageBox::Yes) return false;

    try {
        if (bundle) {
            keystore_->save_contact_bundle(name_str, *bundle);
            if (send_token.size() == 32) keystore_->save_contact_token(name_str, send_token);
        } else {
            keystore_->save_contact(name_str, pub_kem, pub_dsa);
        }
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Add Contact", qstr(e.what()));
        return false;
    }

    // The user confirmed the fingerprint above, so they count as verified in the chats too.
    if (chat_widget_) chat_widget_->mark_verified(fp);
    refresh_contacts();
    int idx = recipient_combo_->findData(name);
    if (idx >= 0) recipient_combo_->setCurrentIndex(idx);
    update_status("Contact added: " + name_str);

    // The card may suggest a relay server. Never switch silently: a card can come from anyone.
    if (auto suggested = parse_server_address(card_server)) {
        auto current = configured_server(server_edit_);
        if (!current || !same_server(*current, *suggested)) {
            QMessageBox ask(QMessageBox::Question, "Relay Server",
                            name + "'s card suggests this relay server:\n\n" + qstr(format_server_address(*suggested)) +
                            "\n\nYour current setting is:\n\n" +
                            (current ? qstr(format_server_address(*current)) : server_edit_->text()) +
                            "\n\nSwitch to the suggested server? Only do this if you recognise it.",
                            QMessageBox::Yes | QMessageBox::No, this);
            ask.setTextFormat(Qt::PlainText);
            if (ask.exec() == QMessageBox::Yes) {
                server_edit_->setText(qstr(format_server_address(*suggested)));
                save_server_setting();
            }
        }
    }
    return true;
}

void MainWindow::remove_contact() {
    QString name = recipient_combo_->currentData().toString();
    if (name.isEmpty()) return;  // "Myself"
    if (QMessageBox::question(this, "Remove Contact", "Remove " + name + " and their keys?") != QMessageBox::Yes)
        return;
    try {
        keystore_->delete_contact(name.toStdString());
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Remove Contact", qstr(e.what()));
        return;
    }
    refresh_contacts();
    update_status("Contact removed: " + name.toStdString());
}

// Our contact card: a messaging card (with its own permission to message us) when messaging is set up, else a plain signed card.
std::optional<QString> MainWindow::own_card_text() {
    if (chat_widget_ && chat_widget_->is_set_up()) return chat_widget_->make_card_text();
    QSettings settings;
    bool ok = false;
    QString name = QInputDialog::getText(this, "Contact Card", "Your name, as your contacts will see it:",
                                         QLineEdit::Normal,
                                         settings.value("display_name", default_display_name()).toString(), &ok).trimmed();
    if (!ok || name.isEmpty()) return std::nullopt;
    if (name.toUtf8().size() > 64) {
        QMessageBox::warning(this, "Contact Card", "Please use a shorter name (64 bytes at most).");
        return std::nullopt;
    }
    settings.setValue("display_name", name);

    std::string relay_hint;
    if (auto server = configured_server(server_edit_)) relay_hint = format_server_address(*server);
    try {
        return qstr(encode_contact_card_v2(keystore_->make_own_bundle(name.toStdString(), relay_hint)));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Contact Card", qstr(e.what()));
        return std::nullopt;
    }
}

// What to tell the user once their card is on its way: what it holds, and the fingerprint their contact should check.
void MainWindow::show_card_note(const QString& where) {
    const bool messaging = chat_widget_ && chat_widget_->is_set_up();
    QMessageBox info(QMessageBox::Information, "Contact Card",
                     "Your contact card is " + where + "\n\n"
                     "It contains only public information, and it is signed with your identity key, so it can't be altered on "
                     "the way without being noticed." +
                         QString(messaging ? " It also carries a permission to message you that belongs to this card alone." : "") +
                         " A signature can't say who made a card, though, so ask your contact to check this fingerprint with "
                         "you in person or on a call when they add you:\n\n" +
                         formatted_fingerprint(keystore_->own_fingerprint()),
                     QMessageBox::Ok, this);
    info.setTextFormat(Qt::PlainText);
    info.exec();
}

void MainWindow::copy_contact_card() {
    auto card = own_card_text();
    if (!card) return;
    QGuiApplication::clipboard()->setText(*card);
    show_card_note("on the clipboard. Paste it into a message to your contact.");
    update_status("Contact card copied to clipboard");
}

void MainWindow::save_contact_card() {
    // Where first: cancelling then makes no card (a messaging card would otherwise use up a permission for nothing).
    const QString path = QFileDialog::getSaveFileName(this, "Save your contact card", QDir(QDir::homePath()).filePath("my-contact-card.txt"),
                                                      "Text files (*.txt);;All files (*)");
    if (path.isEmpty()) return;
    auto card = own_card_text();
    if (!card) return;
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text) || file.write(card->toUtf8()) < 0) {
        QMessageBox::warning(this, "Contact Card", "Could not save the card: " + file.errorString());
        return;
    }
    file.close();
    show_card_note("saved in " + path + ". Send that file to your contact.");
    update_status("Contact card saved");
}

void MainWindow::export_keys() {
    QString dir = QFileDialog::getExistingDirectory(this, "Choose a folder for your public keys");
    if (dir.isEmpty()) return;
    try {
        keystore_->export_public_keys(std::filesystem::u8path(dir.toStdString()));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "Export Keys", qstr(e.what()));
        return;
    }
    QMessageBox info(QMessageBox::Information, "Export Keys",
                     "Saved pq_public_kem.key and pq_public_dsa.key to:\n" + dir +
                     "\n\nThese are public and safe to send by email or chat. Ask your contact to "
                     "check this fingerprint with you when they add you:\n\n" +
                     formatted_fingerprint(keystore_->own_fingerprint()),
                     QMessageBox::Ok, this);
    info.setTextFormat(Qt::PlainText);
    info.exec();
}

// --- Transfers ---

void MainWindow::save_server_setting() {
    QSettings().setValue(SERVER_SETTING, server_edit_->text().trimmed());
    update_relay_label();
}

void MainWindow::update_relay_label() {
    if (!relay_label_) return;
    const QString server = server_edit_->text().trimmed();
    relay_label_->setText(server.isEmpty() ? QString("No relay set for files") : "Using relay " + server);
}

void MainWindow::start_send() {
    if (busy_) return;

    auto server = configured_server(server_edit_);
    if (!server) {
        QMessageBox::warning(this, "Send File", "Enter the relay server as host or host:port.");
        return;
    }
    const std::string host = server->host;
    const uint16_t port = server->port;

    QString contact_name = recipient_combo_->currentData().toString();
    std::optional<KeyStore::Contact> recipient =
        contact_name.isEmpty() ? std::optional<KeyStore::Contact>(keystore_->self_contact())
                               : keystore_->load_contact(contact_name.toStdString());
    if (!recipient) {
        QMessageBox::warning(this, "Send File", "The keys for " + contact_name + " are missing or invalid.");
        return;
    }
    if (!recipient->kem_verified) {
        QMessageBox warn(QMessageBox::Warning, "Encryption key not verified",
                         contact_name + "'s encryption key came from an older card or from key files, so nothing "
                         "proves it is really theirs. If it was altered on the way to you, whoever did it could "
                         "read this file.\n\nAsk " + contact_name + " to update the app and send you a new "
                         "contact card, then add it with +.\n\nSend anyway?",
                         QMessageBox::Yes | QMessageBox::No, this);
        warn.setTextFormat(Qt::PlainText);
        warn.setDefaultButton(QMessageBox::No);
        if (warn.exec() != QMessageBox::Yes) return;
    }

    QString filepath = QFileDialog::getOpenFileName(this, "Select File to Send");
    if (filepath.isEmpty()) return;

    save_server_setting();
    last_server_ = *server;
    progress_bar_->setValue(0);
    transfer_id_label_->clear();
    current_transfer_id_.clear();
    current_share_link_.clear();
    copy_link_button_->setEnabled(false);
    copy_id_button_->setEnabled(false);

    const auto pin = trusted_relay_for(host, port);
    engine_.set_trusted_relay(pin);
    run_in_background([this, path = filepath.toStdString(), host, port, contact = *recipient, pin] {
        auto remember = make_scope_exit([&] { remember_relay(host, port, pin); });
        engine_.upload_file(path, host, port, contact);
    });
}

void MainWindow::start_receive() {
    if (busy_) return;

    auto server = configured_server(server_edit_);
    if (!server) {
        QMessageBox::warning(this, "Receive File", "Enter the relay server as host or host:port.");
        return;
    }
    std::string host = server->host;
    uint16_t port = server->port;

    // The Receive card's box (UX step 4), rather than a separate prompt.
    QString input = receive_edit_->text().trimmed();
    if (input.isEmpty()) {
        QMessageBox::information(this, "Receive a file", "Paste the link or transfer ID you were sent into the box first.");
        receive_edit_->setFocus();
        return;
    }

    std::string id = input.toStdString();
    if (input.startsWith("pqft://", Qt::CaseInsensitive)) {
        auto link = parse_share_link(id);
        if (!link) {
            QMessageBox::warning(this, "Receive File", "That share link isn't valid. Check that it was copied completely.");
            return;
        }
        id = link->transfer_id;

        // A link names its own relay. It can come from anyone, so ask before using it.
        if (!same_server(link->server, *server)) {
            QMessageBox box(QMessageBox::Question, "Relay Server",
                            "This link uses a different relay server than the one you have set.\n\n"
                            "Link:  " + qstr(format_server_address(link->server)) +
                            "\nYours: " + qstr(format_server_address(*server)) +
                            "\n\nWhich should be used for this download?",
                            QMessageBox::NoButton, this);
            box.setTextFormat(Qt::PlainText);
            QAbstractButton* use_link = box.addButton("Use the link's server", QMessageBox::AcceptRole);
            QAbstractButton* use_mine = box.addButton("Use my server", QMessageBox::AcceptRole);
            box.addButton(QMessageBox::Cancel);
            box.exec();
            if (box.clickedButton() == use_link) {
                host = link->server.host;
                port = link->server.port;
            } else if (box.clickedButton() != use_mine) {
                return;
            }
        }
    }

    save_server_setting();
    progress_bar_->setValue(0);
    transfer_id_label_->setText("Receiving: " + qstr(id));
    copy_link_button_->setEnabled(false);
    copy_id_button_->setEnabled(false);

    std::string output_dir = keystore_->downloads_dir().u8string();
    const auto pin = trusted_relay_for(host, port);
    engine_.set_trusted_relay(pin);
    run_in_background([this, id, host, port, output_dir, pin] {
        auto remember = make_scope_exit([&] { remember_relay(host, port, pin); });
        engine_.download_file(id, host, port, output_dir);
    });
}

// Which relay ID the Files tab insists on for host:port: messaging's relay, if it is the same one; otherwise the one seen the
// first time this address was used (trust on first use). Empty if neither: the connection is then accepted and remembered.
std::vector<uint8_t> MainWindow::trusted_relay_for(const std::string& host, uint16_t port) {
    if (auto config = keystore_->load_mailbox_config(); config && config->host == host && config->port == port) return config->relay_id;
    QSettings settings;
    const QString saved = settings.value("relay_pins/" + qstr(host) + ":" + QString::number(port)).toString();
    auto bytes = hex_to_bytes(saved.toStdString());
    return bytes ? *bytes : std::vector<uint8_t>();
}

void MainWindow::remember_relay(const std::string& host, uint16_t port, const std::vector<uint8_t>& pin) {
    if (!pin.empty()) return;  // already trusted
    const auto seen = engine_.relay_seen();
    if (seen.empty()) return;
    QSettings settings;
    settings.setValue("relay_pins/" + qstr(host) + ":" + QString::number(port), qstr(bytes_to_hex(seen)));
}

void MainWindow::run_in_background(std::function<void()> job) {
    if (worker_thread_.joinable()) worker_thread_.join();  // previous job has finished
    set_busy(true);
    update_status("Working...");

    worker_thread_ = std::thread([this, job = std::move(job)] {
        try {
            job();
        } catch (const std::exception& e) {
            QMetaObject::invokeMethod(this, [this, msg = std::string(e.what())] { show_error(msg); });
        } catch (...) {
            QMetaObject::invokeMethod(this, [this] { show_error("Unexpected error"); });
        }
        QMetaObject::invokeMethod(this, [this] { set_busy(false); });
    });
}

void MainWindow::set_busy(bool busy) {
    busy_ = busy;
    send_button_->setEnabled(!busy);
    receive_button_->setEnabled(!busy);
    add_contact_button_->setEnabled(!busy);
    remove_contact_button_->setEnabled(!busy);
    key_protection_button_->setEnabled(!busy);
    copy_card_button_->setEnabled(!busy);
    export_keys_button_->setEnabled(!busy);
    server_edit_->setEnabled(!busy);
    recipient_combo_->setEnabled(!busy);
    cancel_button_->setEnabled(busy);
    if (receive_edit_) receive_edit_->setEnabled(!busy);
    if (change_relay_button_) change_relay_button_->setEnabled(!busy);
    if (progress_row_) progress_row_->setVisible(busy);
    if (busy && result_box_) result_box_->setVisible(false);  // a new transfer: the last link no longer applies
}

void MainWindow::copy_share_link() {
    if (current_share_link_.isEmpty()) return;
    QGuiApplication::clipboard()->setText(current_share_link_);
    update_status("Share link copied to clipboard");
}

void MainWindow::copy_transfer_id() {
    if (current_transfer_id_.isEmpty()) return;
    QGuiApplication::clipboard()->setText(current_transfer_id_);
    update_status("Transfer ID copied to clipboard");
}

void MainWindow::open_downloads() {
    QString dir = qstr(keystore_->downloads_dir().u8string());
    QDir().mkpath(dir);
    QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
}

// --- Display ---

void MainWindow::update_status(const std::string& msg) {
    status_label_->setText("Status: " + qstr(msg));
    status_label_->setStyleSheet("");
}

void MainWindow::update_progress(double fraction) {
    if (progress_bar_) progress_bar_->setValue(static_cast<int>(std::clamp(fraction, 0.0, 1.0) * 100));
}

void MainWindow::show_error(const std::string& error) {
    status_label_->setText("Error: " + qstr(error));
    status_label_->setStyleSheet(QString("color: ") + app_colors::error + ";");
    if (progress_bar_) progress_bar_->setValue(0);
}

void MainWindow::show_complete(const std::string& filepath) {
    // The engine's last status message already says what happened.
    status_label_->setToolTip(qstr(filepath));
    status_label_->setStyleSheet(QString("color: ") + app_colors::success + ";");
    if (progress_bar_) progress_bar_->setValue(100);
}

void MainWindow::show_transfer_id(const std::string& id) {
    current_transfer_id_ = qstr(id);
    current_share_link_ = qstr(build_share_link(last_server_, id));
    transfer_id_label_->setText("Give the recipient this link. It works once, and expires in 24 hours. Only their app can open the file.\n\n" +
                                current_share_link_);
    copy_link_button_->setEnabled(true);
    copy_id_button_->setEnabled(true);
    if (result_box_) result_box_->setVisible(true);
}
