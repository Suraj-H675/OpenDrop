#pragma once

#include <QDialog>
#include <QString>

namespace opendrop {

// Presentation-only: untrusted values from the offered transfer.
// Contains no session exporter, private approval token or destination lease.
struct IncomingOfferView {
    QString claimedDevice;
    QString peerFingerprint;
    QString transferId;
    QString fileName;
    QString fileSha256;
    quint64 byteCount = 0;
    QString initiallySelectedDirectory;
};

// Qt widget only: no network, D-Bus or public permission issuer.
// A destination returned here is NOT a ConsentTicket.
class IncomingOfferDialog final : public QDialog {
public:
    explicit IncomingOfferDialog(IncomingOfferView offer, QWidget *parent = nullptr);

    QString selectedDirectoryAfterAcceptance() const;

private:
    QString selectedDirectory_;
    bool acceptedFromUi_ = false;
};

} // namespace opendrop
