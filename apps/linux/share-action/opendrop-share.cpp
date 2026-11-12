// OpenDrop P1-A: native Dolphin selection handoff, NOT a transfer engine.
// Uses the session D-Bus rather than a shell or a custom network protocol.
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QFileInfo>
#include <QStringList>

#include <cstdio>

namespace {
constexpr int kMaxSelections = 64;

int run(const QStringList &arguments) {
    if (arguments.isEmpty() || arguments.size() > kMaxSelections) {
        std::fputs("OpenDrop: select between 1 and 64 local files.\n", stderr);
        return 2;
    }
    QStringList localPaths;
    for (const QString &path : arguments) {
        const QFileInfo selected(path);
        // Reject non-local, missing, directories and symlink entries for this
        // first-file slice. Later folder support is a separate Level 1 task.
        if (!selected.isAbsolute() || !selected.exists() || !selected.isFile()
            || selected.isSymLink() || selected.canonicalFilePath().isEmpty()) {
            std::fputs("OpenDrop: selection is not an available regular local file.\n", stderr);
            return 2;
        }
        localPaths << selected.canonicalFilePath();
    }

    const auto bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) {
        std::fputs("OpenDrop: desktop session bus unavailable.\n", stderr);
        return 3;
    }
    QDBusInterface recipient("org.opendrop.OpenDrop",
                             "/org/opendrop/OpenDrop",
                             "org.opendrop.Share",
                             bus);
    recipient.setTimeout(2500);
    if (!recipient.isValid()) {
        std::fputs("OpenDrop: background application not running.\n", stderr);
        return 3;
    }
    // QueueFiles is an intended *local* application handoff. A true result
    // means queued for UI presentation, NOT peer consent or file transfer.
    QDBusReply<bool> reply = recipient.call("QueueFiles", localPaths);
    if (!reply.isValid() || !reply.value()) {
        std::fputs("OpenDrop: could not hand off selected files.\n", stderr);
        return 3;
    }
    return 0;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication application(argc, argv);
    return run(application.arguments().mid(1));
}
