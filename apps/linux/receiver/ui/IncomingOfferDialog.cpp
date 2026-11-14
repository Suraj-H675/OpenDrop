#include "IncomingOfferDialog.hpp"

#include <QDialogButtonBox>
#include <QFileDialog>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <utility>

namespace opendrop {

IncomingOfferDialog::IncomingOfferDialog(IncomingOfferView offer, QWidget *parent)
    : QDialog(parent), selectedDirectory_(offer.initiallySelectedDirectory) {
    setWindowTitle(QStringLiteral("OpenDrop — Incoming file"));
    setModal(true);
    setWindowModality(Qt::ApplicationModal);
    setMinimumWidth(430);

    auto *layout = new QVBoxLayout(this);
    auto *warning = new QLabel(
        QStringLiteral("An unverified device wants to send you a file. "
                       "Inspect the details before choosing Accept."),
        this);
    warning->setWordWrap(true);
    layout->addWidget(warning);

    const auto addDetail = [this, layout](const QString &title, const QString &value) {
        auto *line = new QLabel(this);
        line->setTextFormat(Qt::PlainText);
        line->setText(title + QStringLiteral(": ") + value);
        line->setWordWrap(true);
        line->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(line);
    };
    addDetail(QStringLiteral("Claimed sender"), offer.claimedDevice);
    addDetail(QStringLiteral("Certificate fingerprint"), offer.peerFingerprint);
    addDetail(QStringLiteral("Transfer ID"), offer.transferId);
    addDetail(QStringLiteral("Filename"), offer.fileName);
    addDetail(QStringLiteral("Bytes"), QString::number(offer.byteCount));
    addDetail(QStringLiteral("SHA-256"), offer.fileSha256);

    auto *destination = new QLabel(this);
    destination->setTextFormat(Qt::PlainText);
    destination->setTextInteractionFlags(Qt::TextSelectableByMouse);
    destination->setWordWrap(true);
    const auto refreshDestination = [this, destination]() {
        destination->setText(QStringLiteral("Destination: ") + selectedDirectory_);
    };
    refreshDestination();
    layout->addWidget(destination);

    auto *choose = new QPushButton(QStringLiteral("Choose folder…"), this);
    layout->addWidget(choose);
    connect(choose, &QPushButton::clicked, this, [this, refreshDestination]() {
        const QString path = QFileDialog::getExistingDirectory(
            this, QStringLiteral("Choose local destination"), selectedDirectory_,
            QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
        if (!path.isEmpty()) {
            selectedDirectory_ = path;
            refreshDestination();
        }
    });

    auto *buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("Accept file"));
    buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("Decline"));
    layout->addWidget(buttons);
    // Only this widget's actual Accept button activation changes the local
    // UI result. Merely calling QDialog::accept() cannot return a usable
    // owner-action selection through selectedDirectoryAfterAcceptance().
    connect(buttons->button(QDialogButtonBox::Ok), &QPushButton::clicked, this, [this]() {
        if (selectedDirectory_.isEmpty() || !isVisible() ||
            !pinDirectory_ || !pinDirectory_(selectedDirectory_)) {
            return; // no destination was selected by the owner
        }
        acceptedFromUi_ = true;
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    // Full UI expiration must later be bound to the core session/offer lease.
    QTimer::singleShot(120000, this, &QDialog::reject);
}

void IncomingOfferDialog::setLocalDirectoryPin(
    std::function<bool(const QString &)> pin) {
    pinDirectory_ = std::move(pin);
}

QString IncomingOfferDialog::selectedDirectoryAfterAcceptance() const {
    if (!acceptedFromUi_ || result() != QDialog::Accepted) {
        return {};
    }
    return selectedDirectory_;
}

} // namespace opendrop
