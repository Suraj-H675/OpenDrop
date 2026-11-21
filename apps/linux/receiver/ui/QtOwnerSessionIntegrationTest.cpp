#include <QApplication>
#include <QPushButton>
#include <QWidget>

#include <chrono>
#include <iostream>
#include <thread>

extern "C" int opendrop_qt_foreground_start() noexcept;
extern "C" int opendrop_qt_foreground_stop_requested() noexcept;
extern "C" void opendrop_qt_foreground_poll() noexcept;
extern "C" void opendrop_qt_foreground_status(const char *) noexcept;
extern "C" void opendrop_qt_foreground_shutdown() noexcept;
extern "C" int opendrop_qt_take_guest_visibility_action() noexcept;
extern "C" void opendrop_qt_guest_visibility_available(int available) noexcept;

int main() {
    if (opendrop_qt_foreground_start() != 1) {
        std::cerr << "Could not open the native Qt window.\n";
        return 1;
    }
    opendrop_qt_guest_visibility_available(1);
    opendrop_qt_foreground_status(
        "Click Allow guest requests for 10 minutes once to verify this owner session.");
    opendrop_qt_foreground_poll();

    QPushButton *enableGuests = nullptr;
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        for (QPushButton *button : widget->findChildren<QPushButton *>()) {
            if (button->text() == QStringLiteral("Allow guest requests for 10 minutes")) {
                enableGuests = button;
                break;
            }
        }
    }
    if (!enableGuests || !enableGuests->isEnabled()) {
        std::cerr << "This test requires an active local Wayland or X11 logind session.\n";
        opendrop_qt_foreground_shutdown();
        return 2;
    }

    std::cout << "Click the enabled guest button manually in the OpenDrop window." << std::endl;
    while (opendrop_qt_foreground_stop_requested() == 0) {
        opendrop_qt_foreground_poll();
        const int action = opendrop_qt_take_guest_visibility_action();
        if (action == 1) {
            std::cout << "The genuine Qt click passed the owner-session gate.\n";
            opendrop_qt_foreground_shutdown();
            return 0;
        }
        if (action == -1) {
            std::cerr << "The owner-session gate rejected the click.\n";
            opendrop_qt_foreground_shutdown();
            return 3;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    std::cerr << "The OpenDrop window stopped before a guest-button click.\n";
    opendrop_qt_foreground_shutdown();
    return 4;
}
