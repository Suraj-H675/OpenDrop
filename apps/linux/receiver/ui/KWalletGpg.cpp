// Copyright OpenDrop contributors.
// Explicit, fail-closed KWallet6 GPG identity entry. Neither the presence of
// org.freedesktop.secrets nor a KWallet API success proves GPG at-rest storage:
// this adapter INSPECTS the exact dedicated wallet container and refuses all
// unknown/Blowfish cipher headers. A real owner GPG/provisioning audit remains
// a separate physical release gate.
#include <KWallet>
#include <QApplication>
#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QThread>

#include <array>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr const char *WalletName = "OpenDropGpg";
constexpr const char *Folder = "OpenDropIdentity";
constexpr const char *Entry = "Identity.P256.PKCS8.v1";
constexpr int MaxKeyBytes = 512;
constexpr std::array<unsigned char, 16> GpgWalletHeader{
    'K','W','A','L','L','E','T','\n','\r',0,'\r','\n',0,1,2,0
};

// No symbolic links, no group/other access, exact filename and GPG cipher.
// KDE backendpersisthandler: 12-byte magic + 4-byte version where cipher=2.
bool isDedicatedEncryptedWallet() {
    const QString root = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    if (root.isEmpty() || !root.startsWith('/')) return false;
    const QByteArray folder = QFile::encodeName(root + QStringLiteral("/kwalletd"));
    const int directory = ::open(folder.constData(), O_RDONLY | O_DIRECTORY |
        O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return false;
    struct stat dirInfo {};
    const bool dirOk = ::fstat(directory, &dirInfo) == 0 &&
        S_ISDIR(dirInfo.st_mode) && dirInfo.st_uid == ::geteuid() &&
        !(dirInfo.st_mode & 0022);
    if (!dirOk) { ::close(directory); return false; }
    const int file = ::openat(directory, "OpenDropGpg.kwl",
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    ::close(directory);
    if (file < 0) return false;
    struct stat info {};
    std::array<unsigned char, 16> header {};
    const bool ok = ::fstat(file, &info) == 0 &&
        S_ISREG(info.st_mode) && info.st_uid == ::geteuid() &&
        !(info.st_mode & 0077) && info.st_size >= 60 &&
        ::read(file, header.data(), header.size()) ==
            static_cast<ssize_t>(header.size()) && header == GpgWalletHeader;
    ::close(file);
    return ok;
}

// Backend provenance: on today's KDE the KWallet6 D-Bus facade may be a
// proxy for ANY Secret Service provider, regardless of a stale .kwl file.
// We require a write to the exact owner-selected entry's wallet to change
// the actual GPG-encrypted .kwl file. This rejects silent proxy fallback.
QByteArray encryptedWalletDigest() {
    if (!isDedicatedEncryptedWallet()) return {};
    const QString root = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    QFile file(root + QStringLiteral("/kwalletd/OpenDropGpg.kwl"));
    if (!file.open(QIODevice::ReadOnly) || file.size() < 60 ||
        file.size() > (4 * 1024 * 1024)) return {};
    return QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256);
}

bool assertGpgWritePath(KWallet::Wallet *wallet) {
    if (!wallet || !wallet->setFolder(QString::fromLatin1(Folder))) return false;
    const auto before = encryptedWalletDigest();
    if (before.size() != 32) return false;
    QByteArray marker(16, '\0');
    for (int n = 0; n < marker.size(); n += 4) {
        const quint32 random = QRandomGenerator::system()->generate();
        std::memcpy(marker.data() + n, &random, 4);
    }
    const bool wrote = wallet->writeEntry(
        QStringLiteral("GpgBackendSessionProof.v1"), marker) == 0 &&
        wallet->sync() == 0;
    marker.fill(0);
    const auto after = encryptedWalletDigest();
    return wrote && after.size() == 32 && before != after &&
        isDedicatedEncryptedWallet();
}

bool inOwnerQtThread() {
    auto *app = qobject_cast<QApplication *>(QApplication::instance());
    return app && QThread::currentThread() == app->thread();
}

std::unique_ptr<KWallet::Wallet> openExistingGpgWallet() {
    if (!inOwnerQtThread() || !isDedicatedEncryptedWallet() ||
        !KWallet::Wallet::isEnabled() ||
        !KWallet::Wallet::walletList().contains(QString::fromLatin1(WalletName))) {
        return {};
    }
    // The existing GPG wallet must have been independently created by the
    // owner in KDE Wallet Manager. The application cannot create wallets or
    // change their cipher/backend implicitly.
    auto wallet = std::unique_ptr<KWallet::Wallet>(
        KWallet::Wallet::openWallet(QString::fromLatin1(WalletName), 0,
            KWallet::Wallet::Synchronous));
    if (!wallet || !wallet->isOpen() || !isDedicatedEncryptedWallet()) {
        return {};
    }
    return wallet;
}

bool checkArguments(unsigned char *buffer, int capacity) {
    return buffer && capacity >= MaxKeyBytes;
}
} // namespace

// Called BEFORE network activation from the application's UI thread only.
// Binary PKCS#8 travels solely in process-memory Qt/Rust buffers, not stdout,
// logging, command-line, environment or temporary plaintext file.
extern "C" int opendrop_kwallet_gpg_read(unsigned char *buffer, int capacity) noexcept {
    if (!checkArguments(buffer, capacity)) return -1;
    std::memset(buffer, 0, static_cast<size_t>(capacity));
    try {
        auto wallet = openExistingGpgWallet();
        if (!wallet || !wallet->hasFolder(QString::fromLatin1(Folder)) ||
            !wallet->setFolder(QString::fromLatin1(Folder)) ||
            !wallet->hasEntry(QString::fromLatin1(Entry)) ||
            !assertGpgWritePath(wallet.get())) return -1;
        QByteArray secret;
        const bool ok = wallet->readEntry(QString::fromLatin1(Entry), secret) == 0 &&
            secret.size() >= 64 && secret.size() <= MaxKeyBytes &&
            isDedicatedEncryptedWallet();
        const auto size = secret.size();
        if (ok) std::memcpy(buffer, secret.constData(), static_cast<size_t>(size));
        secret.fill(0);
        return ok ? size : -1;
    } catch (...) {
        std::memset(buffer, 0, static_cast<size_t>(capacity));
        return -1;
    }
}

// Explicit owner provisioning mode only, NEVER an automatic replacement
// after missing/locked/lost identity. A GPG wallet MUST already exist.
extern "C" int opendrop_kwallet_gpg_provision(
    const unsigned char *pkcs8, int length) noexcept {
    if (!pkcs8 || length < 64 || length > MaxKeyBytes) return -1;
    try {
        auto wallet = openExistingGpgWallet();
        if (!wallet || wallet->hasFolder(QString::fromLatin1(Folder)) &&
            wallet->setFolder(QString::fromLatin1(Folder)) &&
            wallet->hasEntry(QString::fromLatin1(Entry))) return -1;
        if (!wallet->hasFolder(QString::fromLatin1(Folder)) &&
            !wallet->createFolder(QString::fromLatin1(Folder))) return -1;
        if (!wallet->setFolder(QString::fromLatin1(Folder)) ||
            wallet->hasEntry(QString::fromLatin1(Entry))) return -1;
        QByteArray key(reinterpret_cast<const char *>(pkcs8), length);
        const auto before = encryptedWalletDigest();
        const int wrote = wallet->writeEntry(QString::fromLatin1(Entry), key);
        key.fill(0);
        if (wrote != 0 || wallet->sync() != 0 || !isDedicatedEncryptedWallet() ||
            before.size() != 32 || encryptedWalletDigest() == before ||
            !assertGpgWritePath(wallet.get())) {
            return -1;
        }
        return 1;
    } catch (...) {
        return -1;
    }
}
