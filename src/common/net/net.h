// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>
#include "common/common_types.h"

namespace Common::Net {

struct Asset {
    std::string name;
    std::string url;
    std::string path;
    std::string filename;
    // Expected SHA-256 of the file as "sha256:<hex>", or empty when the host publishes none.
    std::string digest;
};

struct Release {
    std::string title;
    std::string body;
    std::string tag;
    std::string base_download_url;
    std::string html_url;
    std::string host;

    std::vector<std::string> assets;
    // Digest for the asset at the same index of |assets|; empty when the host publishes none.
    std::vector<std::string> asset_digests;

    u64 id;
    u64 published;
    bool prerelease;

    // Expected digest for an asset URL, or an empty string when the host does not publish one.
    std::string GetAssetDigest(std::string_view url) const;

    // Get the relevant list of assets for the current platform.
    std::vector<Asset> GetPlatformAssets() const;
    std::vector<Asset> GetPlatformAssets(std::string_view platform) const;

    static std::optional<Release> FromJson(const nlohmann::json& json, const std::string &host, const std::string& repo);
    static std::optional<Release> FromJson(const std::string_view& json, const std::string &host, const std::string& repo);
    static std::vector<Release> ListFromJson(const nlohmann::json &json, const std::string &host, const std::string &repo);
    static std::vector<Release> ListFromJson(const std::string_view &json, const std::string &host, const std::string &repo);
};

// Make a request via httplib, and return the response body if applicable.
std::optional<std::string> MakeRequest(const std::string &url, const std::string &path);

// Get the latest releases, including prereleases.
std::vector<Release> GetReleases();

// Get the latest releases as text.
std::optional<std::string> GetReleasesBody();

}
