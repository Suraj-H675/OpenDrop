#include "IncomingOfferDialog.hpp"

#include <QApplication>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QTest>
#include <QTimer>

// Pure headless native-widget tests: synthetic QTest clicks do not prove a
// physical owner, compositor seat, rustls connection, or ticket issuance.
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    opendrop::IncomingOfferView view{
        QStringLiteral("untrusted sender"),
        QStringLiteral("certificate fingerprint"),
        QStringLiteral("transfer ID"),
        QStringLiteral("file.txt"),
        QStringLiteral("sha256"),
        4,
        QStringLiteral("/tmp")
    };

    {
        opendrop::IncomingOfferDialog dialog(view);
        QTimer::singleShot(0, &dialog, [&dialog] {
            dialog.accept(); // bypass the button: must never become consent
        });
        if (dialog.exec() != QDialog::Accepted ||
            !dialog.selectedDirectoryAfterAcceptance().isEmpty()) {
            return 1;
        }
    }
    {
        opendrop::IncomingOfferDialog dialog(view);
        QTimer::singleShot(0, &dialog, [&dialog] {
            auto *buttons = dialog.findChild<QDialogButtonBox *>();
            if (!buttons) {
                dialog.reject();
                return;
            }
            QTest::mouseClick(buttons->button(QDialogButtonBox::Ok), Qt::LeftButton);
        });
        if (dialog.exec() != QDialog::Accepted ||
            dialog.selectedDirectoryAfterAcceptance() != QStringLiteral("/tmp")) {
            return 2;
        }
    }
    {
        opendrop::IncomingOfferDialog dialog(view);
        QTimer::singleShot(0, &dialog, [&dialog] { dialog.reject(); });
        if (dialog.exec() != QDialog::Rejected ||
            !dialog.selectedDirectoryAfterAcceptance().isEmpty()) {
            return 3;
        }
    }
    return 0;
}
