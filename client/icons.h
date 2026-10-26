#pragma once

#include <QColor>
#include <QIcon>
#include <QPixmap>
#include <QString>

// Line icons (24×24, drawn with a 1.75 px stroke), built into the app as SVG and drawn in whatever colour a button needs.
// They need Qt's SVG module: CMake enables them (PQ_HAVE_SVG) when it finds Qt6::Svg. Without it every icon is empty, and
// the app shows text (and the emoji it used before) instead: check app_icons_available() where that matters.
// Names: chat, user-plus, upload, download, settings, paperclip, plus, users, hourglass, send.
bool app_icons_available();
QPixmap app_icon_pixmap(const QString& name, int size, const QColor& color);
QIcon app_icon(const QString& name, const QColor& color = QColor("#ececee"));
class QAbstractButton;
// Puts an icon on a button, with a gap before its text (Qt otherwise draws them almost touching). No-op without icons.
void set_button_icon(QAbstractButton* button, const QString& name, const QColor& color = QColor("#ececee"));
