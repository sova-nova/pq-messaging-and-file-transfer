#pragma once

#include <cstdint>
#include <vector>

#include <QString>

class QListWidget;

// One chat as a two-line row (UX polish): a round avatar (an initial, or an icon for groups and Private chats), the name in
// bold, a muted second line ("Verified", "Group · 3 members", "Private · 1 day after reading"), the date of the last
// activity, and an unread badge. Used by the Chats list and Home's recent chats.
struct ChatEntry {
    QString key;       // "c:" + contact fingerprint, "g:" + group ID, "p:" + Private chat ID
    QString title;     // untrusted text (a name): shown as plain text only
    QString subtitle;
    QString tooltip;
    QString icon;      // an app_icon name for the avatar; empty: the title's first letter
    QString fallback;  // the avatar's text when there is no icon support (e.g. ⏳)
    int64_t when = 0;  // last activity, unix seconds (0: none)
    size_t unread = 0;
    bool dimmed = false;  // can't be written to at the moment
};

// Fills `list` with one row per entry; each item keeps its entry's key in Qt::UserRole.
void fill_chat_list(QListWidget* list, const std::vector<ChatEntry>& entries);
// "14:05" today, "23 Oct" this year, else "23 Oct 2025".
QString short_when(int64_t unix_seconds);
