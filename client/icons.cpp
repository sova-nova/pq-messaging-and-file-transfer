#include "icons.h"

#include <QAbstractButton>

#ifdef PQ_HAVE_SVG
#include <QByteArray>
#include <QGuiApplication>
#include <QPainter>
#include <QSvgRenderer>
#endif

namespace {

const char* icon_body(const QString& name) {
    if (name == "chat") return R"(<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>)";
    if (name == "user-plus") return R"(<path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><path d="M20 8v6M23 11h-6"/>)";
    if (name == "upload") return R"(<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/>)";
    if (name == "download") return R"(<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>)";
    if (name == "settings")
        return R"(<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>)";
    if (name == "paperclip") return R"(<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>)";
    if (name == "plus") return R"(<path d="M12 5v14M5 12h14"/>)";
    if (name == "users") return R"(<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>)";
    if (name == "hourglass") return R"(<path d="M6 2h12M6 22h12M7 2v4l5 6-5 6v4M17 2v4l-5 6 5 6v4"/>)";
    if (name == "send") return R"(<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/>)";
    return nullptr;
}

}  // namespace

bool app_icons_available() {
#ifdef PQ_HAVE_SVG
    return true;
#else
    return false;
#endif
}

QPixmap app_icon_pixmap(const QString& name, int size, const QColor& color) {
#ifdef PQ_HAVE_SVG
    const char* body = icon_body(name);
    if (!body) return QPixmap();
    const QByteArray svg = QByteArray("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"") +
                           color.name().toLatin1() + "\" stroke-width=\"1.75\" stroke-linecap=\"round\" stroke-linejoin=\"round\">" + body + "</svg>";
    QSvgRenderer renderer(svg);
    if (!renderer.isValid()) return QPixmap();
    const qreal ratio = qGuiApp ? qGuiApp->devicePixelRatio() : 1.0;  // sharp on high-DPI screens
    QPixmap pixmap(static_cast<int>(size * ratio), static_cast<int>(size * ratio));
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    renderer.render(&painter);
    painter.end();
    pixmap.setDevicePixelRatio(ratio);
    return pixmap;
#else
    (void)name;
    (void)size;
    (void)color;
    return QPixmap();
#endif
}

QIcon app_icon(const QString& name, const QColor& color) {
    const QPixmap pixmap = app_icon_pixmap(name, 32, color);
    return pixmap.isNull() ? QIcon() : QIcon(pixmap);
}

void set_button_icon(QAbstractButton* button, const QString& name, const QColor& color) {
    const QIcon icon = app_icon(name, color);
    if (icon.isNull()) return;
    button->setIcon(icon);
    if (!button->text().isEmpty() && !button->text().startsWith(' ')) button->setText("  " + button->text());
}
