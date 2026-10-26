#pragma once

class QApplication;

// The app's own look (UX step 7): always dark, the same on every system. Qt's Fusion style with a dark palette, plus one
// style sheet. Widgets opt into a look with a "role" property instead of their own colours, so the look lives in one place:
//   QPushButton  role = "primary"      the main action on a screen (blue)
//                role = "link"         a quiet secondary action, drawn like a link
//                role = "tile"         Home's big buttons ("tile-primary": the blue one)
//                role = "info"         a highlighted row that needs attention (the "waiting for you" row)
//                role = "warning"      the action in a warning banner
//   QWidget      role = "warning-banner" / "info-banner"   a tinted, rounded strip (needs Qt::WA_StyledBackground)
// Combo boxes, menus and scroll bars are deliberately left to Fusion and the palette: styling their parts with a style
// sheet makes Qt drop the combo box's arrow and menus' check marks.
void apply_app_style(QApplication& app);

class QWidget;
// The spacing scale, applied to a page or dialog once it's built: 16 px around the page and inside every card (group box),
// 12 px between things. A dialog also never gets smaller than its contents (so nothing in it can overlap).
void apply_spacing(QWidget* root);

// Colours for the few places that set one in code.
namespace app_colors {
constexpr const char* error = "#ff8a80";
constexpr const char* success = "#6fd0b0";
constexpr const char* warning = "#f0b65a";
}  // namespace app_colors
