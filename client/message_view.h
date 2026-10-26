#pragma once

#include <functional>
#include <vector>

#include <QString>
#include <QTextBrowser>

// One message as the chat shows it.
struct MessageLine {
    QString text;            // what is shown: always plain text, never HTML or links
    bool outgoing = false;   // ours (on the right) or theirs (on the left)
    QString copy_text;       // what "Copy message" puts on the clipboard (empty: the text as shown)
    QString attachment_id;   // an attachment: double-click shows what can be done with it
    QString delivery_id;     // a group message of ours: double-click shows who has received it
    QString private_id;      // a Private chat message: right-click can delete it (and take it back, if `retractable`)
    bool retractable = false;
    QString tooltip;
};

// The messages of the chat on screen, as read-only text that can be selected freely: words inside one message, or across
// several, copied with Ctrl+C or the right-click menu (G1). Messages are inserted as plain text only, so nothing anyone sends
// can add markup, images or links. The view is redrawn only when what it shows has changed, and then keeps the selection and
// the scroll position (unless asked to scroll to the end, or the chat on screen is a different one).
class MessageView : public QTextBrowser {
public:
    explicit MessageView(QWidget* parent = nullptr);

    // `scope` names the chat the lines belong to: a different scope starts afresh (no selection kept, scrolled to the end).
    void set_lines(const QString& scope, std::vector<MessageLine> lines, bool scroll_to_end);
    // The message at a point in the view (viewport coordinates), if any.
    const MessageLine* line_at(const QPoint& pos) const;

    // Double-click on a message: return true if it was handled (otherwise the word under the pointer is selected, as usual).
    std::function<bool(const MessageLine& line)> on_double_click;
    // Right-click: `line` is the message under the pointer, or null.
    std::function<void(const MessageLine* line, const QPoint& global_pos)> on_context_menu;

protected:
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    bool viewportEvent(QEvent* event) override;

private:
    QString scope_;
    std::vector<MessageLine> lines_;
};
