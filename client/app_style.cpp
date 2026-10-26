#include "app_style.h"

#include <QApplication>
#include <QColor>
#include <QPalette>
#include <QDialog>
#include <QGroupBox>
#include <QLayout>
#include <QStyleFactory>
#include <QWidget>

namespace {

const char* STYLE_SHEET = R"(
QLabel { background: transparent; }
QLabel[role="title"] { font-size: 13pt; font-weight: 600; }
QLabel[role="section"] { font-weight: 600; color: #c4c4ca; padding-top: 8px; }
QLabel[role="muted"] { color: #b6b6bd; }
QLabel[role="note"] { color: #b6b6bd; }
QPushButton[role="icon-menu"] { padding: 8px 14px; }
QPushButton[role="icon-menu"]::menu-indicator { image: none; width: 0px; }
QLabel[role="tile-title"] { font-size: 12pt; font-weight: 600; }
QLabel[role="tile-text"] { color: #b6b6bd; }
QPushButton[role="tile-primary"] QLabel { color: #ffffff; }
QPushButton[role="tile-primary"] QLabel[role="tile-text"] { color: #ffffff; }
QLabel[role="avatar"] { background: #44506a; color: #ffffff; border-radius: 18px; font-weight: 600; }
QLabel[role="entry-title"] { font-weight: 600; }
QLabel[role="entry-title-dim"] { font-weight: 600; color: #aaaab2; }
QLabel[role="entry-sub"], QLabel[role="entry-when"] { color: #b6b6bd; font-size: 9pt; }
QLabel[role="badge"] { background: #2f6bc4; color: #ffffff; border-radius: 9px; padding: 0 6px; font-size: 9pt; font-weight: 600; min-height: 18px; }
QToolTip { background: #36363a; color: #ececee; border: 1px solid #55555c; padding: 4px; }

QPushButton {
    background: #36363a; color: #ececee; border: 1px solid #55555c; border-radius: 6px;
    padding: 8px 16px; min-height: 20px;
}
QPushButton:hover { background: #3f3f44; border-color: #6a6a72; }
QPushButton:pressed { background: #2f2f33; }
QPushButton:focus { border-color: #5b8fd6; }
QPushButton:disabled { background: #303033; color: #7a7a80; border-color: #44444a; }

QPushButton[role="primary"] { background: #2f6bc4; border: 1px solid #2f6bc4; color: #ffffff; font-weight: 600; }
QPushButton[role="primary"]:hover { background: #285ea9; border-color: #285ea9; }
QPushButton[role="primary"]:pressed { background: #234f8f; }
QPushButton[role="primary"]:focus { border-color: #a9c7f0; }
QPushButton[role="primary"]:disabled { background: #2b3a52; border-color: #2b3a52; color: #8f9bb0; }

QPushButton[role="link"] { background: transparent; border: 1px solid transparent; color: #8fb8ef; padding: 2px 4px; text-align: left; }
QPushButton[role="link"]:hover { color: #b5d0f5; text-decoration: underline; }
QPushButton[role="link"]:focus { border-color: #5b8fd6; }
QPushButton[role="link"]:disabled { color: #6a7a90; }

QPushButton[role="tile"], QPushButton[role="tile-primary"] {
    min-height: 96px; border-radius: 12px; padding: 14px 18px; text-align: left; font-size: 11pt;
}
QPushButton[role="tile"] { background: #323236; border: 1px solid #4a4a50; }
QPushButton[role="tile"]:hover { background: #3a3a3f; border-color: #6a6a72; }
QPushButton[role="tile-primary"] { background: #2f6bc4; border: 1px solid #2f6bc4; color: #ffffff; font-weight: 600; }
QPushButton[role="tile-primary"]:hover { background: #285ea9; }

QPushButton[role="info"] { background: #2b3444; border: 1px solid #3f5372; text-align: left; padding: 8px 12px; }
QPushButton[role="info"]:hover { background: #33405a; }
QPushButton[role="warning"] { background: #f0b65a; border: 1px solid #f0b65a; color: #2a2008; font-weight: 600; }
QPushButton[role="warning"]:hover { background: #f5c57a; }

QWidget[role="warning-banner"] { background: #3a3022; border: 1px solid #7a5c2a; border-radius: 8px; }
QWidget[role="warning-banner"] QLabel { color: #f3d4a2; }
QWidget[role="info-banner"] { background: #2b3444; border: 1px solid #3f5372; border-radius: 8px; }

QLineEdit, QPlainTextEdit, QTextBrowser, QListWidget {
    background: #1f1f21; color: #ececee; border: 1px solid #4a4a50; border-radius: 6px;
    selection-background-color: #2f6bc4; selection-color: #ffffff;
}
QLineEdit { padding: 7px 10px; min-height: 20px; }
QLineEdit:focus, QPlainTextEdit:focus, QTextBrowser:focus, QListWidget:focus { border-color: #5b8fd6; }
QLineEdit:disabled { color: #7a7a80; }

QListWidget { padding: 4px; outline: 0; }
QListWidget::item { padding: 8px 6px; border-radius: 6px; }
QListWidget::item:hover { background: #303036; }
QListWidget::item:selected { background: #3a3f4a; color: #ffffff; }

/* A card's title sits inside it, in space its layout reserves (apply_spacing: a 40 px top margin). Not above it with
   margin-top: Qt leaves that space out of a group box's minimum size, so a dialog came out short and squeezed its contents
   (Add a contact's paste box overlapped the label beneath it). */
QGroupBox {
    background: #2f2f32; border: 1px solid #45454b; border-radius: 10px;
    margin-top: 0; padding: 0; font-weight: 600;
}
QGroupBox::title { subcontrol-origin: padding; subcontrol-position: top left; left: 16px; top: 12px; padding: 0; color: #ececee; }

QTabWidget::pane { border: none; border-top: 1px solid #45454b; }
QTabBar::tab { background: transparent; color: #c4c4ca; padding: 10px 16px; border: none; border-bottom: 3px solid transparent; }
QTabBar::tab:selected { color: #ffffff; border-bottom: 3px solid #2f6bc4; font-weight: 600; }
QTabBar::tab:hover:!selected { color: #ececee; }

QProgressBar { background: #1f1f21; border: 1px solid #4a4a50; border-radius: 6px; text-align: center; color: #ececee; min-height: 18px; }
QProgressBar::chunk { background: #2f6bc4; border-radius: 5px; }

QCheckBox, QRadioButton { spacing: 8px; }
)";

}  // namespace

void apply_app_style(QApplication& app) {
    app.setStyle(QStyleFactory::create("Fusion"));  // draws the same everywhere, and follows the style sheet faithfully

    QPalette p;
    const QColor window("#262628"), base("#1f1f21"), text("#ececee"), button("#36363a"), disabled("#7a7a80");
    p.setColor(QPalette::Window, window);
    p.setColor(QPalette::WindowText, text);
    p.setColor(QPalette::Base, base);
    p.setColor(QPalette::AlternateBase, QColor("#2a2a2d"));
    p.setColor(QPalette::ToolTipBase, button);
    p.setColor(QPalette::ToolTipText, text);
    p.setColor(QPalette::PlaceholderText, QColor("#8a8a92"));
    p.setColor(QPalette::Text, text);
    p.setColor(QPalette::Button, button);
    p.setColor(QPalette::ButtonText, text);
    p.setColor(QPalette::BrightText, QColor("#ffffff"));
    p.setColor(QPalette::Link, QColor("#8fb8ef"));
    p.setColor(QPalette::Highlight, QColor("#2f6bc4"));
    p.setColor(QPalette::HighlightedText, QColor("#ffffff"));
    p.setColor(QPalette::Light, QColor("#4a4a50"));
    p.setColor(QPalette::Midlight, QColor("#3a3a3e"));
    p.setColor(QPalette::Mid, QColor("#2f2f33"));
    p.setColor(QPalette::Dark, QColor("#1a1a1c"));
    p.setColor(QPalette::Shadow, QColor("#000000"));
    for (auto role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText}) p.setColor(QPalette::Disabled, role, disabled);
    app.setPalette(p);
    app.setStyleSheet(STYLE_SHEET);
}

void apply_spacing(QWidget* root) {
    if (!root) return;
    if (QLayout* l = root->layout()) {
        l->setContentsMargins(16, 16, 16, 16);
        l->setSpacing(12);
        if (qobject_cast<QDialog*>(root)) l->setSizeConstraint(QLayout::SetMinimumSize);  // never smaller than its contents
    }
    for (QGroupBox* box : root->findChildren<QGroupBox*>()) {
        if (QLayout* l = box->layout()) {
            l->setContentsMargins(16, 40, 16, 16);  // the top 40 holds the card's title (see the style sheet)
            l->setSpacing(10);
        }
    }
}
