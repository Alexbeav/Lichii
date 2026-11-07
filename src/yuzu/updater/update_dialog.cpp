// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include <QRadioButton>
#include <QSaveFile>
#include <QStandardPaths>
#include <qdesktopservices.h>
#include "common/logging.h"
#include "qt_common/abstract/frontend.h"
#include "qt_common/abstract/progress.h"
#include "ui_update_dialog.h"
#include "update_dialog.h"

#include "common/httplib.h"

#ifdef YUZU_BUNDLED_OPENSSL
#include <openssl/cert.h>
#endif

#include <openssl/evp.h>

#include <QDesktopServices>

#undef GetSaveFileName

namespace {

// Checks a downloaded file against the digest the release host publishes ("sha256:<hex>").
// Verification is skipped when the host publishes no digest for the asset.
class DigestVerifier {
public:
    explicit DigestVerifier(std::string expected) : m_expected{std::move(expected)} {
        constexpr std::string_view prefix{"sha256:"};
        if (m_expected.starts_with(prefix)) {
            m_expected.erase(0, prefix.size());
        }
        if (m_expected.empty()) {
            return;
        }
        m_ctx = EVP_MD_CTX_new();
        if (m_ctx != nullptr && EVP_DigestInit_ex(m_ctx, EVP_sha256(), nullptr) == 1) {
            m_enabled = true;
        }
    }

    ~DigestVerifier() {
        if (m_ctx != nullptr) {
            EVP_MD_CTX_free(m_ctx);
        }
    }

    DigestVerifier(const DigestVerifier&) = delete;
    DigestVerifier& operator=(const DigestVerifier&) = delete;

    // False when there is no published digest, so nothing can be verified.
    bool CanVerify() const {
        return m_enabled;
    }

    bool Update(const char* data, std::size_t size) {
        if (!m_enabled) {
            return true;
        }
        return EVP_DigestUpdate(m_ctx, data, size) == 1;
    }

    bool Matches() {
        if (!m_enabled) {
            return true;
        }
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int size{0};
        if (EVP_DigestFinal_ex(m_ctx, digest.data(), &size) != 1) {
            return false;
        }
        static constexpr char hex_digits[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(size * 2);
        for (unsigned int i = 0; i < size; ++i) {
            hex += hex_digits[digest[i] >> 4];
            hex += hex_digits[digest[i] & 0xf];
        }
        return hex == m_expected;
    }

private:
    std::string m_expected;
    EVP_MD_CTX* m_ctx{};
    bool m_enabled{};
};

} // namespace

UpdateDialog::UpdateDialog(const Common::Net::Release& release, QWidget* parent)
    : QDialog(parent), ui(new Ui::UpdateDialog) {
    ui->setupUi(this);

    ui->version->setText(
        tr("%1 is available for download.").arg(QString::fromStdString(release.title)));
    ui->url->setText(
        tr("<a href=\"%1\">View on GitHub</a>").arg(QString::fromStdString(release.html_url)));

    std::string text{release.body};
    if (auto pos = text.find("# Packages"); pos != std::string::npos) {
        text = text.substr(0, pos);
    }

    ui->body->setMarkdown(QString::fromStdString(text));

    // TODO(crueter): Find a way to set default
    const auto assets = release.GetPlatformAssets();

    if (assets.empty()) {
        ui->groupBox->setHidden(true);
        connect(this, &QDialog::accepted, this, [release]() {
            QDesktopServices::openUrl(QUrl{QString::fromStdString(release.html_url)});
        });
    } else if (assets.size() == 1) {
        ui->groupBox->setHidden(true);
        m_asset = assets[0];

        connect(this, &QDialog::accepted, this, &UpdateDialog::Download);
    } else {
        u32 i = 0;
        for (const Common::Net::Asset& a : assets) {
            QRadioButton* r = new QRadioButton(tr(a.name.c_str()), this);
            connect(r, &QRadioButton::toggled, this, [a, this](bool checked) {
                if (checked)
                    m_asset = a;
            });

            if (i == 0)
                r->setChecked(true);
            ++i;

            ui->radioButtons->addWidget(r);
        }

        connect(this, &QDialog::accepted, this, &UpdateDialog::Download);
    }
}

UpdateDialog::~UpdateDialog() {
    delete ui;
}

// TODO: migrate to a net.cpp wrapper
void UpdateDialog::Download() {
    const auto filename = QtCommon::Frontend::GetSaveFileName(
        tr("New Version Location"),
        qApp->applicationDirPath() % QStringLiteral("/") % QString::fromStdString(m_asset.filename),
        tr("All Files (*.*)"));

    if (filename.isEmpty())
        return;

    QSaveFile file(filename);
    if (!file.open(QIODevice::Truncate | QIODevice::WriteOnly)) {
        LOG_WARNING(Frontend, "Could not open file {}", filename.toStdString());
        QtCommon::Frontend::Critical(tr("Failed to save file"),
                                     tr("Could not open file %1 for writing.").arg(filename));
        return;
    }

    // The release host publishes a SHA-256 for each asset; compare what arrives against it.
    DigestVerifier digest{m_asset.digest};
    if (!digest.CanVerify()) {
        LOG_INFO(Frontend, "No published digest for {}, the download cannot be verified",
                 m_asset.filename);
    }

    // TODO(crueter): Move to net.cpp
    constexpr std::size_t timeout_seconds = 15;

    std::unique_ptr<httplib::Client> client = std::make_unique<httplib::Client>(m_asset.url);
    client->set_connection_timeout(timeout_seconds);
    client->set_read_timeout(timeout_seconds);
    client->set_write_timeout(timeout_seconds);
    client->set_follow_location(true);

#ifdef YUZU_BUNDLED_OPENSSL
    client->load_ca_cert_store(kCert, sizeof(kCert));
#endif

    if (client == nullptr) {
        LOG_ERROR(Frontend, "Invalid URL {}{}", m_asset.url, m_asset.path);
        return;
    }

    auto progress =
        QtCommon::Frontend::newProgressDialog(tr("Downloading..."), tr("Cancel"), 0, 100);
    progress->show();

    QGuiApplication::processEvents();

    // Progress dialog.
    auto progress_callback = [&](size_t processed_size, size_t total_size) {
        QGuiApplication::processEvents();
        if (total_size != 0) {
            progress->setValue(static_cast<int>((processed_size * 100) / total_size));
        }
        return !progress->wasCanceled();
    };

    // Write file in chunks, hashing as we go.
    auto content_receiver = [&file, filename, &digest](const char* t_data,
                                                       size_t data_length) -> bool {
        if (!digest.Update(t_data, data_length)) {
            LOG_ERROR(Frontend, "Could not hash {} bytes for {}", data_length,
                      filename.toStdString());
            return false;
        }

        if (file.write(t_data, data_length) == -1) {
            LOG_WARNING(Frontend, "Could not write {} bytes to file {}", data_length,
                        filename.toStdString());
            QtCommon::Frontend::Critical(tr("Failed to save file"),
                                         tr("Could not write to file %1.").arg(filename));
            return false;
        }

        return true;
    };

    // Now send off request
    auto result = client->Get(m_asset.path, content_receiver, progress_callback);
    progress->close();

    if (!result) {
        LOG_ERROR(Frontend, "GET to {}{} returned null", m_asset.url, m_asset.path);
        return;
    }

    const auto& response = result.value();
    if (response.status >= 400) {
        LOG_ERROR(Frontend, "GET to {}{} returned error status code: {}", m_asset.url, m_asset.path,
                  response.status);
        QtCommon::Frontend::Critical(tr("Failed to download file"),
                                     tr("Could not download from %1%2\nError code: %3")
                                         .arg(QString::fromStdString(m_asset.url),
                                              QString::fromStdString(m_asset.path),
                                              QString::number(response.status)));
        return;
    }
    if (!response.has_header("content-type")) {
        LOG_ERROR(Frontend, "GET to {}{} returned no content", m_asset.url, m_asset.path);
        return;
    }

    if (!digest.Matches()) {
        LOG_ERROR(Frontend, "{} does not match the digest published for this release",
                  m_asset.filename);
        file.cancelWriting();
        QtCommon::Frontend::Critical(
            tr("Failed to verify download"),
            tr("%1 does not match the SHA-256 published for this release. The file was "
               "discarded; download it again from the release page.")
                .arg(QString::fromStdString(m_asset.filename)));
        return;
    }

    if (!file.commit()) {
        LOG_WARNING(Frontend, "Could not commit to file {}", filename.toStdString());
        QtCommon::Frontend::Critical(tr("Failed to save file"),
                                     tr("Could not commit to file %1.").arg(filename));
        return;
    }

    // Download is complete. User may choose to open in the file manager.
    auto button =
        QtCommon::Frontend::Question(tr("Download Complete"),
                                     tr("Successfully downloaded %1. Would you like to open it?")
                                         .arg(QString::fromStdString(m_asset.filename)),
                                     QtCommon::Frontend::Yes | QtCommon::Frontend::No);

    if (button == QtCommon::Frontend::Yes) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(filename));
    }
}
