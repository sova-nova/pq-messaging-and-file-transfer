#include "chat_entry.h"

#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QListWidgetItem>
#include <QVBoxLayout>

#include "icons.h"

namespace {

QLabel* row_label(const QString& text, const char* role, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setTextFormat(Qt::PlainText);  // names are other people's text: never markup
    label->setProperty("role", role);
    label->setAttribute(Qt::WA_TransparentForMouseEvents);  // clicks, hover and selection belong to the list
    return label;
}

QWidget* make_row(const ChatEntry& e, QWidget* parent) {
    auto* row = new QWidget(parent);
    row->setAttribute(Qt::WA_TransparentForMouseEvents);
    auto* layout = new QHBoxLayout(row);
    layout->setContentsMargins(4, 2, 4, 2);
    layout->setSpacing(10);

    auto* avatar = row_label(QString(), "avatar", row);
    avatar->setFixedSize(36, 36);
    avatar->setAlignment(Qt::AlignCenter);
    const QPixmap icon = e.icon.isEmpty() ? QPixmap() : app_icon_pixmap(e.icon, 18, QColor("#ffffff"));
    if (!icon.isNull()) avatar->setPixmap(icon);
    else if (!e.icon.isEmpty() && !e.fallback.isEmpty()) avatar->setText(e.fallback);
    else avatar->setText(e.title.isEmpty() ? QString("?") : e.title.left(1).toUpper());
    layout->addWidget(avatar);

    auto* text = new QVBoxLayout();
    text->setSpacing(1);
    text->addWidget(row_label(e.title, e.dimmed ? "entry-title-dim" : "entry-title", row));
    if (!e.subtitle.isEmpty()) text->addWidget(row_label(e.subtitle, "entry-sub", row));
    layout->addLayout(text, 1);

    auto* side = new QVBoxLayout();
    side->setSpacing(2);
    side->addWidget(row_label(short_when(e.when), "entry-when", row), 0, Qt::AlignRight);
    if (e.unread) side->addWidget(row_label(QString::number(static_cast<qulonglong>(e.unread)), "badge", row), 0, Qt::AlignRight);
    side->addStretch(1);
    layout->addLayout(side);
    return row;
}

}  // namespace

QString short_when(int64_t unix_seconds) {
    if (unix_seconds <= 0) return QString();
    const QDateTime when = QDateTime::fromSecsSinceEpoch(unix_seconds);
    const QDate today = QDate::currentDate();
    if (when.date() == today) return when.toString("HH:mm");
    if (when.date().year() == today.year()) return when.toString("d MMM");
    return when.toString("d MMM yyyy");
}

void fill_chat_list(QListWidget* list, const std::vector<ChatEntry>& entries) {
    list->clear();
    for (const auto& e : entries) {
        auto* item = new QListWidgetItem();  // no visible text: the row widget draws it (text here would show underneath)
        item->setData(Qt::UserRole, e.key);
        item->setData(Qt::AccessibleTextRole, e.title + (e.subtitle.isEmpty() ? QString() : ", " + e.subtitle));
        item->setToolTip(e.tooltip);
        item->setSizeHint(QSize(0, 58));
        list->addItem(item);
        list->setItemWidget(item, make_row(e, list));
    }
}
