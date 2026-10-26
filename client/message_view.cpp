#include "message_view.h"

#include <algorithm>

#include <QContextMenuEvent>
#include <QHelpEvent>
#include <QMouseEvent>
#include <QScrollBar>
#include <QTextBlock>
#include <QTextBlockFormat>
#include <QTextCursor>
#include <QTextDocument>
#include <QToolTip>

MessageView::MessageView(QWidget* parent) : QTextBrowser(parent) {
    setOpenLinks(false);  // there are none (everything is plain text), and nothing should ever open
    setOpenExternalLinks(false);
    setUndoRedoEnabled(false);
    setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
}

void MessageView::set_lines(const QString& scope, std::vector<MessageLine> lines, bool scroll_to_end) {
    const bool same_scope = scope == scope_;
    bool unchanged = same_scope && lines.size() == lines_.size();
    for (size_t i = 0; unchanged && i < lines.size(); i++) unchanged = lines[i].text == lines_[i].text && lines[i].outgoing == lines_[i].outgoing;
    if (unchanged) {
        lines_ = std::move(lines);  // what the lines lead to may have changed; how they look hasn't
        if (scroll_to_end) verticalScrollBar()->setValue(verticalScrollBar()->maximum());
        return;
    }
    QScrollBar* bar = verticalScrollBar();
    const bool was_at_end = bar->value() >= bar->maximum() - 4;
    const int old_value = bar->value();
    const QTextCursor old_cursor = textCursor();
    const bool keep_selection = same_scope && old_cursor.hasSelection();
    const int anchor = old_cursor.anchor(), position = old_cursor.position();

    document()->clear();
    QTextCursor c(document());
    for (size_t i = 0; i < lines.size(); i++) {
        QTextBlockFormat format;
        format.setAlignment((lines[i].outgoing ? Qt::AlignRight : Qt::AlignLeft) | Qt::AlignAbsolute);
        format.setBottomMargin(6);
        if (i == 0) c.setBlockFormat(format);
        else c.insertBlock(format);
        QString text = lines[i].text;
        text.replace(QChar('\n'), QChar(QChar::LineSeparator));  // one block per message, so a block always maps to one message
        c.insertText(text);  // plain text: never interpreted as markup
        c.block().setUserState(static_cast<int>(i));
    }
    lines_ = std::move(lines);
    scope_ = scope;

    if (keep_selection) {
        const int last = document()->characterCount() - 1;
        QTextCursor restored(document());
        restored.setPosition(std::min(anchor, last));
        restored.setPosition(std::min(position, last), QTextCursor::KeepAnchor);
        setTextCursor(restored);
    }
    if (scroll_to_end || !same_scope || was_at_end) bar->setValue(bar->maximum());
    else bar->setValue(old_value);
}

const MessageLine* MessageView::line_at(const QPoint& pos) const {
    const int index = cursorForPosition(pos).block().userState();
    if (index < 0 || static_cast<size_t>(index) >= lines_.size()) return nullptr;
    return &lines_[static_cast<size_t>(index)];
}

void MessageView::mouseDoubleClickEvent(QMouseEvent* event) {
    const MessageLine* line = line_at(event->position().toPoint());
    if (line && on_double_click && on_double_click(*line)) {
        event->accept();
        return;
    }
    QTextBrowser::mouseDoubleClickEvent(event);
}

void MessageView::contextMenuEvent(QContextMenuEvent* event) {
    if (!on_context_menu) {
        QTextBrowser::contextMenuEvent(event);
        return;
    }
    on_context_menu(line_at(event->pos()), event->globalPos());
    event->accept();
}

bool MessageView::viewportEvent(QEvent* event) {
    if (event->type() == QEvent::ToolTip) {
        auto* help = static_cast<QHelpEvent*>(event);
        const MessageLine* line = line_at(help->pos());
        if (line && !line->tooltip.isEmpty()) QToolTip::showText(help->globalPos(), line->tooltip, viewport());
        else QToolTip::hideText();
        return true;
    }
    return QTextBrowser::viewportEvent(event);
}
