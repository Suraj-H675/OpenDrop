#include "IncomingOfferDialog.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QThread>
#include <QTimer>
#include <QByteArray>
#include <QEventLoop>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

#include <systemd/sd-login.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <optional>
#include <atomic>
#include <csignal>
#include <memory>
#include <string>
#include <utility>

namespace {

std::unique_ptr<QApplication> foregroundApp;
std::unique_ptr<QWidget> foregroundWindow;
QLabel *foregroundStatus = nullptr;
std::atomic<bool> foregroundStop{false};
volatile std::sig_atomic_t caughtShutdownSignal = 0;

void foreground_signal(int) {
    caughtShutdownSignal = 1;
}

} // namespace

// A visible owner-controlled foreground window remains alive outside modal
// approvals. It registers no D-Bus endpoint or remote click capability.
extern "C" int opendrop_qt_foreground_start() noexcept {
    try {
        if (QCoreApplication::instance()) {
            return -1;
        }
        static int argc = 1;
        static char name[] = "opendrop-linux-receiver";
        static char *argv[] = {name, nullptr};
        foregroundApp = std::make_unique<QApplication>(argc, argv);
        foregroundApp->setQuitOnLastWindowClosed(false);
        foregroundStop.store(false, std::memory_order_release);
        caughtShutdownSignal = 0;
        std::signal(SIGINT, foreground_signal);
        std::signal(SIGTERM, foreground_signal);
        foregroundWindow = std::make_unique<QWidget>();
        foregroundWindow->setWindowTitle(QStringLiteral("OpenDrop — Receiving"));
        foregroundWindow->setMinimumWidth(430);
        auto *layout = new QVBoxLayout(foregroundWindow.get());
        foregroundStatus = new QLabel(
            QStringLiteral("Waiting for a previously paired device."), foregroundWindow.get());
        foregroundStatus->setTextFormat(Qt::PlainText);
        foregroundStatus->setWordWrap(true);
        layout->addWidget(foregroundStatus);
        auto *stop = new QPushButton(QStringLiteral("Stop receiving"), foregroundWindow.get());
        layout->addWidget(stop);
        QObject::connect(stop, &QPushButton::clicked, foregroundWindow.get(), []() {
            foregroundStop.store(true, std::memory_order_release);
        });
        QObject::connect(foregroundApp.get(), &QGuiApplication::lastWindowClosed,
                         []() { foregroundStop.store(true, std::memory_order_release); });
        foregroundWindow->show();
        return 1;
    } catch (...) {
        foregroundStop.store(true, std::memory_order_release);
        return -1;
    }
}

extern "C" int opendrop_qt_foreground_stop_requested() noexcept {
    return (caughtShutdownSignal != 0 || foregroundStop.load(std::memory_order_acquire)) ? 1 : 0;
}

extern "C" void opendrop_qt_foreground_poll() noexcept {
    try {
        if (foregroundApp) {
            if (caughtShutdownSignal != 0) {
                foregroundStop.store(true, std::memory_order_release);
            }
            QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        }
    } catch (...) {
        foregroundStop.store(true, std::memory_order_release);
    }
}

extern "C" void opendrop_qt_foreground_status(const char *message) noexcept {
    try {
        if (foregroundStatus && foregroundApp &&
            QThread::currentThread() == foregroundApp->thread() && message) {
            foregroundStatus->setText(QString::fromUtf8(message));
        }
    } catch (...) {
        foregroundStop.store(true, std::memory_order_release);
    }
}

extern "C" void opendrop_qt_foreground_shutdown() noexcept {
    foregroundStatus = nullptr;
    foregroundWindow.reset();
    foregroundApp.reset();
}

namespace {

// This is a sanity check on the owner desktop process, NOT cryptographic
// proof of physical presence. A same-UID malicious process can compromise
// the trusted app process by other means; no network peer can reach this
// function through the existing OpenDrop protocol or public IPC.
struct OwnerSession {
    std::string name;
    std::string seat;
    uid_t uid;
};

std::optional<OwnerSession> currentOwnerSession() {
    char *sessionName = nullptr;
    if (sd_pid_get_session(0, &sessionName) < 0 || !sessionName) {
        std::free(sessionName);
        return std::nullopt;
    }
    const std::string name(sessionName);
    std::free(sessionName);

    if (sd_session_is_active(name.c_str()) != 1) {
        return std::nullopt;
    }
    uid_t uid = 0;
    if (sd_session_get_uid(name.c_str(), &uid) < 0 || uid != geteuid()) {
        return std::nullopt;
    }
    char *sessionType = nullptr;
    if (sd_session_get_type(name.c_str(), &sessionType) < 0 || !sessionType) {
        return std::nullopt;
    }
    const std::string type(sessionType);
    std::free(sessionType);
    if (type != "wayland" && type != "x11") {
        return std::nullopt;
    }
    char *seat = nullptr;
    if (sd_session_get_seat(name.c_str(), &seat) < 0 || !seat) {
        return std::nullopt;
    }
    const std::string ownerSeat(seat);
    std::free(seat);
    if (ownerSeat.empty()) {
        return std::nullopt;
    }
    return OwnerSession{name, ownerSeat, uid};
}

} // namespace

// THIS IS NOT A CONSENT TICKET ISSUER. Only core Rust can create a ticket.
// ABI is intentionally value-only, with no pointer to AuthenticatedSession,
// exporter secrets, journal, Qt callbacks or privileged native capabilities.
//  1 = owner used the dialog's Accept button with a destination
//  0 = declined/dismissed/timed out
// -1 = wrong process/session/GUI thread/invalid destination
extern "C" int opendrop_qt_present_owner_consent(
    const char *claimedDevice,
    const char *peerFingerprint,
    const char *transferId,
    const char *fileName,
    const char *fileSha256,
    unsigned long long byteCount,
    const char *initialDestination,
    int (*pinOwnerDirectory)(void *, const char *, size_t),
    void *pinContext,
    int (*transportStillActive)(const void *),
    const void *transportContext,
    char *destinationOut,
    size_t destinationCapacity) noexcept {
    try {
        if (!claimedDevice || !peerFingerprint || !transferId ||
            !fileName || !fileSha256 || !initialDestination ||
            !pinOwnerDirectory || !pinContext ||
            !transportStillActive || !transportContext ||
            !destinationOut || destinationCapacity < 2) {
            return -1;
        }
        auto *app = qobject_cast<QApplication *>(QCoreApplication::instance());
        if (!app || QThread::currentThread() != app->thread()) {
            return -1;
        }
        const auto platform = QGuiApplication::platformName();
        if (platform != QStringLiteral("wayland") &&
            platform != QStringLiteral("xcb")) {
            return -1;
        }
        const auto before = currentOwnerSession();
        if (!before) {
            return -1;
        }
        opendrop::IncomingOfferView details{
            QString::fromUtf8(claimedDevice),
            QString::fromUtf8(peerFingerprint),
            QString::fromUtf8(transferId),
            QString::fromUtf8(fileName),
            QString::fromUtf8(fileSha256),
            byteCount,
            QString::fromUtf8(initialDestination)
        };
        opendrop::IncomingOfferDialog dialog(std::move(details));
        QTimer transportWatch(&dialog);
        QObject::connect(&transportWatch, &QTimer::timeout, &dialog, [&dialog,
            transportStillActive, transportContext]() {
            if (caughtShutdownSignal != 0 ||
                foregroundStop.load(std::memory_order_acquire) ||
                transportStillActive(transportContext) != 1) {
                dialog.reject();
            }
        });
        transportWatch.start(150);
        dialog.setLocalDirectoryPin([pinOwnerDirectory, pinContext](
                                        const QString &selected) {
            const QByteArray bytes = selected.toUtf8();
            if (bytes.isEmpty() || bytes.size() > 4096 ||
                bytes.contains('\0')) {
                return false;
            }
            // This callback may ONLY pin and validate an owner directory.
            // No approval capability is issued from the C++ widget.
            return pinOwnerDirectory(
                       pinContext, bytes.constData(),
                       static_cast<size_t>(bytes.size())) == 1;
        });
        if (dialog.exec() != QDialog::Accepted) {
            return 0;
        }
        const auto after = currentOwnerSession();
        if (!after || before->name != after->name ||
            before->seat != after->seat || before->uid != after->uid) {
            return -1;
        }
        // selectedDirectoryAfterAcceptance returns empty on reject, timer,
        // or programmatic QDialog::accept() without its local button handler.
        const auto destination = dialog.selectedDirectoryAfterAcceptance();
        if (destination.isEmpty()) {
            return -1;
        }
        const QByteArray bytes = destination.toUtf8();
        if (bytes.isEmpty() ||
            static_cast<size_t>(bytes.size()) >= destinationCapacity ||
            bytes.contains('\0')) {
            return -1;
        }
        std::memcpy(destinationOut, bytes.constData(),
                    static_cast<size_t>(bytes.size()));
        destinationOut[bytes.size()] = '\0';
        return 1;
    } catch (...) {
        return -1;
    }
}
