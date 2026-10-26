#include "message_view.h"

#include <algorithm>

#include <QDate>
#include <QDateTime>
#include <QContextMenuEvent>
#include <QHelpEvent>
#include <QMouseEvent>
#include <QScrollBar>
#include <QTextBlock>
#include <QTextBlockFormat>
#include <QTextCursor>
#include <QTextDocument>
#include <QColor>
#include <QTextCharFormat>
#include <QTextFrameFormat>
#include <QTextFrame>
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
    for (size_t i = 0; unchanged && i < lines.size(); i++)
        unchanged = lines[i].text == lines_[i].text && lines[i].meta == lines_[i].meta && lines[i].body == lines_[i].body &&
                    lines[i].outgoing == lines_[i].outgoing && lines[i].status == lines_[i].status && lines[i].when == lines_[i].when;
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
    // Each message is a box (a text frame): ours tinted blue and set in from the left, theirs grey and set in from the right,
    // with a small line on top (who, when, status) and the message beneath. Every block in a box carries the message's index
    // as its user state, which is how a click, right-click or tooltip finds its message. Text is only ever inserted as plain
    // text. A line without meta and body (a hint, say) is a plain block with no box.
    const qreal base_size = document()->defaultFont().pointSizeF();
    QTextCharFormat meta_format;
    meta_format.setForeground(QColor("#b4b4bc"));
    if (base_size > 0) meta_format.setFontPointSize(base_size * 0.88);
    const QTextCharFormat body_format;
    auto one_line = [](QString t) { return t.replace(QChar('\n'), QChar(QChar::LineSeparator)); };  // one block per part
    auto block_for = [](bool outgoing, qreal top) {
        QTextBlockFormat b;
        b.setAlignment((outgoing ? Qt::AlignRight : Qt::AlignLeft) | Qt::AlignAbsolute);
        b.setTopMargin(top);
        return b;
    };

    QTextFrame* open_box = nullptr;      // the box the next message may join (grouped mode)
    const MessageLine* last_in_box = nullptr;
    int last_index = -1;
    QDate last_day;
    // A group's status goes once, under its last message, before the box is left behind.
    auto close_box = [&] {
        if (open_box && last_in_box && grouped_ && !last_in_box->status.isEmpty()) {
            QTextCursor c = open_box->lastCursorPosition();
            c.insertBlock(block_for(last_in_box->outgoing, 2));
            c.insertText(last_in_box->status, meta_format);
            c.block().setUserState(last_index);
        }
        open_box = nullptr;
        last_in_box = nullptr;
    };

    for (size_t i = 0; i < lines.size(); i++) {
        const MessageLine& line = lines[i];
        const int index = static_cast<int>(i);
        QTextCursor c = document()->rootFrame()->lastCursorPosition();
        const bool first_block = i == 0 && c.block().text().isEmpty() && !open_box;
        if (line.meta.isEmpty() && line.body.isEmpty()) {  // a hint: plain, no box
            close_box();
            QTextBlockFormat b = block_for(line.outgoing, 0);
            b.setBottomMargin(6);
            if (first_block) c.setBlockFormat(b);
            else c.insertBlock(b);
            c.insertText(one_line(line.text), body_format);
            c.block().setUserState(index);
            continue;
        }
        // Grouped: a quiet line for each new day ("Today", "Yesterday", "23 Oct"), belonging to no message.
        if (grouped_ && line.when > 0) {
            const QDate day = QDateTime::fromSecsSinceEpoch(line.when).date();
            if (day != last_day) {
                close_box();
                last_day = day;
                const QDate today = QDate::currentDate();
                const QString label = day == today ? QString("Today") : day == today.addDays(-1) ? QString("Yesterday")
                                    : day.year() == today.year() ? day.toString("d MMMM") : day.toString("d MMMM yyyy");
                QTextBlockFormat b;
                b.setAlignment(Qt::AlignHCenter);
                b.setTopMargin(first_block ? 0 : 6);
                b.setBottomMargin(6);
                c = document()->rootFrame()->lastCursorPosition();
                if (c.block().text().isEmpty() && i == 0) c.setBlockFormat(b);
                else c.insertBlock(b);
                c.insertText(label, meta_format);
                c.block().setUserState(-1);
            }
        }
        const bool join = grouped_ && open_box && last_in_box && !line.group_key.isEmpty() && line.group_key == last_in_box->group_key &&
                          line.outgoing == last_in_box->outgoing && line.when >= last_in_box->when &&
                          line.when - last_in_box->when <= GROUP_WINDOW_SECONDS;
        if (join) {  // another paragraph in the same box, close beneath the last
            QTextCursor in = open_box->lastCursorPosition();
            in.insertBlock(block_for(line.outgoing, 3));
            in.insertText(one_line(line.body), body_format);
            in.block().setUserState(index);
        } else {
            close_box();
            QTextFrameFormat box;
            box.setBackground(QColor(line.outgoing ? "#24344d" : "#323236"));
            box.setBorder(1);
            box.setBorderBrush(QColor(line.outgoing ? "#3a5680" : "#4a4a50"));
            box.setBorderStyle(QTextFrameFormat::BorderStyle_Solid);
            box.setPadding(7);
            box.setTopMargin(0);
            box.setBottomMargin(5);
            box.setLeftMargin(line.outgoing ? 80 : 0);
            box.setRightMargin(line.outgoing ? 0 : 80);
            c = document()->rootFrame()->lastCursorPosition();
            QTextFrame* frame = c.insertFrame(box);  // the cursor is now inside the box, in its first block
            c.setBlockFormat(block_for(line.outgoing, 0));
            const QString top = grouped_ && !line.meta_short.isEmpty() ? line.meta_short : line.meta;
            c.insertText(one_line(top), meta_format);
            c.block().setUserState(index);
            c.insertBlock(block_for(line.outgoing, 2));
            c.insertText(one_line(line.body), body_format);
            c.block().setUserState(index);
            open_box = frame;
        }
        last_in_box = &line;
        last_index = index;
    }
    close_box();
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

void MessageView::set_grouped(bool grouped) {
    if (grouped == grouped_) return;
    grouped_ = grouped;
    lines_.clear();  // so the next set_lines redraws, even though the messages are the same
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
