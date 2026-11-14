#include <QApplication>
#include <QPushButton>
#include <QTest>
#include <QWidget>

extern "C" int opendrop_qt_foreground_start() noexcept;
extern "C" int opendrop_qt_foreground_stop_requested() noexcept;
extern "C" void opendrop_qt_foreground_poll() noexcept;
extern "C" void opendrop_qt_foreground_status(const char *) noexcept;
extern "C" void opendrop_qt_foreground_shutdown() noexcept;
extern "C" int opendrop_qt_take_guest_visibility_action() noexcept;
extern "C" void opendrop_qt_guest_visibility_available(int available) noexcept;

// Headless window-lifecycle regression only: no TLS, real compositor, local
// owner approval, network listener, filesystem writes or device operations.
int main() {
    if (opendrop_qt_foreground_start() != 1) {
        return 1;
    }
    opendrop_qt_foreground_status("Waiting for already paired peers.");
    opendrop_qt_foreground_poll();
    if (opendrop_qt_foreground_stop_requested() != 0) {
        opendrop_qt_foreground_shutdown();
        return 2;
    }
    // These checks are synthetic widget-state tests, not real human
    // verification or owner-operated Wayland. A disabled guest control
    // must never manufacture an Everyone admission action.
    QPushButton *enableGuests = nullptr;
    QPushButton *revokeGuests = nullptr;
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        for (QPushButton *button : widget->findChildren<QPushButton *>()) {
            if (button->text() == QStringLiteral("Allow guest requests for 10 minutes")) {
                enableGuests = button;
            } else if (button->text() == QStringLiteral("Stop guest requests")) {
                revokeGuests = button;
            }
        }
    }
    if (!enableGuests || !revokeGuests || enableGuests->isEnabled() ||
        revokeGuests->isEnabled()) {
        opendrop_qt_foreground_shutdown();
        return 4;
    }
    QTest::mouseClick(enableGuests, Qt::LeftButton);
    // A headless CI session has no authenticated owner seat. A synthetic
    // click cannot pass the native seat check.
    if (opendrop_qt_take_guest_visibility_action() != -1) {
        opendrop_qt_foreground_shutdown();
        return 5;
    }
    opendrop_qt_guest_visibility_available(1);
    if (!enableGuests->isEnabled() || !revokeGuests->isEnabled()) {
        opendrop_qt_foreground_shutdown();
        return 6;
    }
    bool clicked = false;
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        for (QPushButton *button : widget->findChildren<QPushButton *>()) {
            if (button->text() == QStringLiteral("Stop receiving") && button->isEnabled()) {
                QTest::mouseClick(button, Qt::LeftButton);
                clicked = true;
                break;
            }
        }
        if (clicked) {
            break;
        }
    }
    opendrop_qt_foreground_poll();
    const bool stopped = clicked && opendrop_qt_foreground_stop_requested() == 1;
    opendrop_qt_foreground_shutdown();
    return stopped ? 0 : 3;
}
