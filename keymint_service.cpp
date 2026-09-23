/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "android.hardware.security.keymint-service"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <openssl/sha.h>

#include "AndroidKeyMintDevice.h"
#include "AndroidRemotelyProvisionedComponentDevice.h"
#include "AndroidSecureClock.h"
#include "AndroidSharedSecret.h"
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <keymaster/soft_keymaster_logger.h>

using aidl::android::hardware::security::keymint::Algorithm;
using aidl::android::hardware::security::keymint::AndroidKeyMintDevice;
using aidl::android::hardware::security::keymint::AndroidRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::keymint::AttestationKey;
using aidl::android::hardware::security::keymint::BeginResult;
using aidl::android::hardware::security::keymint::BlockMode;
using aidl::android::hardware::security::keymint::ErrorCode;
using aidl::android::hardware::security::keymint::HardwareAuthToken;
using aidl::android::hardware::security::keymint::KeyCharacteristics;
using aidl::android::hardware::security::keymint::KeyCreationResult;
using aidl::android::hardware::security::keymint::KeyParameter;
using aidl::android::hardware::security::keymint::KeyParameterValue;
using aidl::android::hardware::security::keymint::KeyPurpose;
using aidl::android::hardware::security::keymint::PaddingMode;
using aidl::android::hardware::security::keymint::SecurityLevel;
using aidl::android::hardware::security::keymint::Tag;
using aidl::android::hardware::security::secureclock::AndroidSecureClock;
using aidl::android::hardware::security::sharedsecret::AndroidSharedSecret;

namespace {

constexpr size_t kMetadataKeyAppIdSize = SHA512_DIGEST_LENGTH;
constexpr size_t kMetadataKeyNormalizedAppIdSize = 16;
constexpr std::array<uint8_t, 8> kMetadataKeyBlobMagic = {'T', 'P', 'M', '3', '1', '2', 'A', '1'};
constexpr size_t kMetadataKeyBlobHeaderSize = kMetadataKeyBlobMagic.size() + sizeof(uint64_t);

bool isMetadataKeyRequest(const std::vector<KeyParameter> &keyParams) {
    // Keystore2 adds CREATION_DATETIME for KeyMint v1 and newer before it
    // forwards the request to the HAL. vold itself supplies the nine
    // parameters checked below, so permit that one additional platform tag.
    if (keyParams.size() < 9 || keyParams.size() > 10)
        return false;

    bool hasAppId = false;
    bool hasNoAuth = false;
    bool hasAesAlgorithm = false;
    bool has256BitSize = false;
    bool hasGcm = false;
    bool hasMinMac128 = false;
    bool hasNoPadding = false;
    bool hasEncryptPurpose = false;
    bool hasDecryptPurpose = false;
    bool hasCreationDateTime = false;

    for (const auto &param : keyParams) {
        switch (param.tag) {
        case Tag::APPLICATION_ID:
            if (hasAppId || param.value.getTag() != KeyParameterValue::blob ||
                param.value.get<KeyParameterValue::blob>().size() != kMetadataKeyAppIdSize) {
                return false;
            }
            hasAppId = true;
            break;
        case Tag::NO_AUTH_REQUIRED:
            if (hasNoAuth || param.value.getTag() != KeyParameterValue::boolValue ||
                !param.value.get<KeyParameterValue::boolValue>()) {
                return false;
            }
            hasNoAuth = true;
            break;
        case Tag::ALGORITHM:
            if (hasAesAlgorithm || param.value.getTag() != KeyParameterValue::algorithm ||
                param.value.get<KeyParameterValue::algorithm>() != Algorithm::AES) {
                return false;
            }
            hasAesAlgorithm = true;
            break;
        case Tag::KEY_SIZE:
            if (has256BitSize || param.value.getTag() != KeyParameterValue::integer ||
                param.value.get<KeyParameterValue::integer>() != 256) {
                return false;
            }
            has256BitSize = true;
            break;
        case Tag::BLOCK_MODE:
            if (hasGcm || param.value.getTag() != KeyParameterValue::blockMode ||
                param.value.get<KeyParameterValue::blockMode>() != BlockMode::GCM) {
                return false;
            }
            hasGcm = true;
            break;
        case Tag::MIN_MAC_LENGTH:
            if (hasMinMac128 || param.value.getTag() != KeyParameterValue::integer ||
                param.value.get<KeyParameterValue::integer>() != 128) {
                return false;
            }
            hasMinMac128 = true;
            break;
        case Tag::PADDING:
            if (hasNoPadding || param.value.getTag() != KeyParameterValue::paddingMode ||
                param.value.get<KeyParameterValue::paddingMode>() != PaddingMode::NONE) {
                return false;
            }
            hasNoPadding = true;
            break;
        case Tag::PURPOSE:
            if (param.value.getTag() != KeyParameterValue::keyPurpose)
                return false;
            if (param.value.get<KeyParameterValue::keyPurpose>() == KeyPurpose::ENCRYPT) {
                if (hasEncryptPurpose)
                    return false;
                hasEncryptPurpose = true;
            } else if (param.value.get<KeyParameterValue::keyPurpose>() == KeyPurpose::DECRYPT) {
                if (hasDecryptPurpose)
                    return false;
                hasDecryptPurpose = true;
            } else {
                return false;
            }
            break;
        case Tag::CREATION_DATETIME:
            if (hasCreationDateTime || param.value.getTag() != KeyParameterValue::dateTime)
                return false;
            hasCreationDateTime = true;
            break;
        default:
            return false;
        }
    }

    return hasAppId && hasNoAuth && hasAesAlgorithm && has256BitSize && hasGcm && hasMinMac128 &&
           hasNoPadding && hasEncryptPurpose && hasDecryptPurpose &&
           keyParams.size() == 9 + static_cast<size_t>(hasCreationDateTime);
}

bool hashMetadataAppIdBytes(const std::vector<uint8_t> &appId, std::vector<uint8_t> *digest) {
    if (appId.size() != kMetadataKeyAppIdSize)
        return false;
    std::array<uint8_t, SHA256_DIGEST_LENGTH> fullDigest{};
    if (SHA256(appId.data(), appId.size(), fullDigest.data()) == nullptr)
        return false;
    digest->assign(fullDigest.begin(), fullDigest.begin() + kMetadataKeyNormalizedAppIdSize);
    return true;
}

bool hashMetadataAppId(std::vector<KeyParameter> *keyParams) {
    KeyParameter *appIdParam = nullptr;
    for (auto &param : *keyParams) {
        if (param.tag != Tag::APPLICATION_ID)
            continue;
        if (appIdParam || param.value.getTag() != KeyParameterValue::blob)
            return false;
        appIdParam = &param;
    }
    if (!appIdParam)
        return false;

    const auto &appId = appIdParam->value.get<KeyParameterValue::blob>();
    std::vector<uint8_t> digest;
    if (!hashMetadataAppIdBytes(appId, &digest))
        return false;
    appIdParam->value = KeyParameterValue::make<KeyParameterValue::blob>(std::move(digest));
    return true;
}

enum class MetadataKeyBlobState { UNWRAPPED, WRAPPED, MALFORMED };

MetadataKeyBlobState unwrapMetadataKeyBlob(const std::vector<uint8_t> &keyBlob,
                                           std::vector<uint8_t> *unwrapped) {
    if (keyBlob.size() < kMetadataKeyBlobMagic.size() ||
        !std::equal(kMetadataKeyBlobMagic.begin(), kMetadataKeyBlobMagic.end(), keyBlob.begin())) {
        return MetadataKeyBlobState::UNWRAPPED;
    }
    if (keyBlob.size() < kMetadataKeyBlobHeaderSize)
        return MetadataKeyBlobState::MALFORMED;

    uint64_t payloadSize = 0;
    for (size_t i = 0; i < sizeof(payloadSize); ++i) {
        payloadSize |= static_cast<uint64_t>(keyBlob[kMetadataKeyBlobMagic.size() + i]) << (i * 8);
    }
    const size_t actualSize = keyBlob.size() - kMetadataKeyBlobHeaderSize;
    if (payloadSize == 0 || payloadSize != actualSize)
        return MetadataKeyBlobState::MALFORMED;

    unwrapped->assign(keyBlob.begin() + kMetadataKeyBlobHeaderSize, keyBlob.end());
    return MetadataKeyBlobState::WRAPPED;
}

bool wrapMetadataKeyBlob(const std::vector<uint8_t> &keyBlob, std::vector<uint8_t> *wrapped) {
    if (keyBlob.empty() ||
        keyBlob.size() > std::numeric_limits<size_t>::max() - kMetadataKeyBlobHeaderSize) {
        return false;
    }
    wrapped->assign(kMetadataKeyBlobMagic.begin(), kMetadataKeyBlobMagic.end());
    const uint64_t payloadSize = keyBlob.size();
    for (size_t i = 0; i < sizeof(payloadSize); ++i) {
        wrapped->push_back(static_cast<uint8_t>(payloadSize >> (i * 8)));
    }
    wrapped->insert(wrapped->end(), keyBlob.begin(), keyBlob.end());
    return true;
}

ndk::ScopedAStatus invalidWrappedMetadataKey() {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(ErrorCode::INVALID_KEY_BLOB));
}

} // namespace

// RK's KeyMint implementation is supplied as a prebuilt. Keep TPM312-specific
// compatibility handling in this service so existing TEE key blobs continue
// to use their original parameters.
class RockchipKeyMintDevice : public AndroidKeyMintDevice {
  public:
    explicit RockchipKeyMintDevice(SecurityLevel securityLevel)
        : AndroidKeyMintDevice(securityLevel) {}

    ndk::ScopedAStatus generateKey(const std::vector<KeyParameter> &keyParams,
                                   const std::optional<AttestationKey> &attestationKey,
                                   KeyCreationResult *creationResult) override {
        for (const auto &param : keyParams) {
            if (param.tag == Tag::ROLLBACK_RESISTANCE) {
                LOG(WARNING) << "rejecting rollback-resistant key generation before TEE";
                return ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(ErrorCode::UNSUPPORTED_TAG));
            }
        }

        if (attestationKey.has_value() || !isMetadataKeyRequest(keyParams)) {
            return AndroidKeyMintDevice::generateKey(keyParams, attestationKey, creationResult);
        }

        // vold binds the metadata-encryption key to a 64-byte secdiscardable
        // hash. Pass a fixed-size 128-bit digest to the legacy RK implementation,
        // whose handling of long application IDs is not safe. Keystore2 adds
        // CREATION_DATETIME for KeyMint v1; it is informational only, so keep it
        // out of the legacy Keymaster request. Mark the returned opaque blob so
        // only this key's later operations use the same digest. Unmarked
        // HIDL-era key blobs remain unchanged.
        std::vector<KeyParameter> normalizedParams = keyParams;
        normalizedParams.erase(
            std::remove_if(normalizedParams.begin(), normalizedParams.end(), [](const auto &param) {
                return param.tag == Tag::CREATION_DATETIME;
            }),
            normalizedParams.end());
        if (!hashMetadataAppId(&normalizedParams))
            return invalidWrappedMetadataKey();

        ndk::ScopedAStatus status =
            AndroidKeyMintDevice::generateKey(normalizedParams, attestationKey, creationResult);
        if (!status.isOk())
            return status;
        std::vector<uint8_t> wrappedKeyBlob;
        if (!wrapMetadataKeyBlob(creationResult->keyBlob, &wrappedKeyBlob)) {
            return invalidWrappedMetadataKey();
        }
        creationResult->keyBlob = std::move(wrappedKeyBlob);
        return status;
    }

    ndk::ScopedAStatus begin(KeyPurpose purpose, const std::vector<uint8_t> &keyBlob,
                             const std::vector<KeyParameter> &params,
                             const std::optional<HardwareAuthToken> &authToken,
                             BeginResult *result) override {
        std::vector<uint8_t> unwrappedKeyBlob;
        const auto blobState = unwrapMetadataKeyBlob(keyBlob, &unwrappedKeyBlob);
        if (blobState == MetadataKeyBlobState::UNWRAPPED) {
            return AndroidKeyMintDevice::begin(purpose, keyBlob, params, authToken, result);
        }
        if (blobState == MetadataKeyBlobState::MALFORMED)
            return invalidWrappedMetadataKey();
        std::vector<KeyParameter> normalizedParams = params;
        if (!hashMetadataAppId(&normalizedParams))
            return invalidWrappedMetadataKey();
        return AndroidKeyMintDevice::begin(purpose, unwrappedKeyBlob, normalizedParams, authToken,
                                           result);
    }

    ndk::ScopedAStatus
    getKeyCharacteristics(const std::vector<uint8_t> &keyBlob, const std::vector<uint8_t> &appId,
                          const std::vector<uint8_t> &appData,
                          std::vector<KeyCharacteristics> *characteristics) override {
        std::vector<uint8_t> unwrappedKeyBlob;
        const auto blobState = unwrapMetadataKeyBlob(keyBlob, &unwrappedKeyBlob);
        if (blobState == MetadataKeyBlobState::UNWRAPPED) {
            return AndroidKeyMintDevice::getKeyCharacteristics(keyBlob, appId, appData,
                                                               characteristics);
        }
        if (blobState == MetadataKeyBlobState::MALFORMED)
            return invalidWrappedMetadataKey();
        std::vector<uint8_t> normalizedAppId;
        if (!hashMetadataAppIdBytes(appId, &normalizedAppId))
            return invalidWrappedMetadataKey();
        return AndroidKeyMintDevice::getKeyCharacteristics(unwrappedKeyBlob, normalizedAppId,
                                                           appData, characteristics);
    }

    ndk::ScopedAStatus upgradeKey(const std::vector<uint8_t> &keyBlobToUpgrade,
                                  const std::vector<KeyParameter> &upgradeParams,
                                  std::vector<uint8_t> *keyBlob) override {
        std::vector<uint8_t> unwrappedKeyBlob;
        const auto blobState = unwrapMetadataKeyBlob(keyBlobToUpgrade, &unwrappedKeyBlob);
        if (blobState == MetadataKeyBlobState::UNWRAPPED) {
            return AndroidKeyMintDevice::upgradeKey(keyBlobToUpgrade, upgradeParams, keyBlob);
        }
        if (blobState == MetadataKeyBlobState::MALFORMED)
            return invalidWrappedMetadataKey();
        std::vector<KeyParameter> normalizedParams = upgradeParams;
        if (!hashMetadataAppId(&normalizedParams))
            return invalidWrappedMetadataKey();
        ndk::ScopedAStatus status =
            AndroidKeyMintDevice::upgradeKey(unwrappedKeyBlob, normalizedParams, keyBlob);
        if (!status.isOk())
            return status;
        std::vector<uint8_t> wrappedKeyBlob;
        if (!wrapMetadataKeyBlob(*keyBlob, &wrappedKeyBlob))
            return invalidWrappedMetadataKey();
        *keyBlob = std::move(wrappedKeyBlob);
        return status;
    }

    ndk::ScopedAStatus deleteKey(const std::vector<uint8_t> &keyBlob) override {
        std::vector<uint8_t> unwrappedKeyBlob;
        const auto blobState = unwrapMetadataKeyBlob(keyBlob, &unwrappedKeyBlob);
        if (blobState == MetadataKeyBlobState::UNWRAPPED) {
            return AndroidKeyMintDevice::deleteKey(keyBlob);
        }
        if (blobState == MetadataKeyBlobState::MALFORMED)
            return invalidWrappedMetadataKey();
        return AndroidKeyMintDevice::deleteKey(unwrappedKeyBlob);
    }

    ndk::ScopedAStatus
    convertStorageKeyToEphemeral(const std::vector<uint8_t> &storageKeyBlob,
                                 std::vector<uint8_t> *ephemeralKeyBlob) override {
        std::vector<uint8_t> unwrappedKeyBlob;
        const auto blobState = unwrapMetadataKeyBlob(storageKeyBlob, &unwrappedKeyBlob);
        if (blobState == MetadataKeyBlobState::UNWRAPPED) {
            return AndroidKeyMintDevice::convertStorageKeyToEphemeral(storageKeyBlob,
                                                                      ephemeralKeyBlob);
        }
        if (blobState == MetadataKeyBlobState::MALFORMED)
            return invalidWrappedMetadataKey();
        std::vector<uint8_t> rawEphemeralKeyBlob;
        ndk::ScopedAStatus status = AndroidKeyMintDevice::convertStorageKeyToEphemeral(
            unwrappedKeyBlob, &rawEphemeralKeyBlob);
        if (!status.isOk())
            return status;
        if (!wrapMetadataKeyBlob(rawEphemeralKeyBlob, ephemeralKeyBlob)) {
            return invalidWrappedMetadataKey();
        }
        return status;
    }

    ndk::ScopedAStatus importWrappedKey(const std::vector<uint8_t> &wrappedKeyData,
                                        const std::vector<uint8_t> &wrappingKeyBlob,
                                        const std::vector<uint8_t> &maskingKey,
                                        const std::vector<KeyParameter> &unwrappingParams,
                                        int64_t passwordSid, int64_t biometricSid,
                                        KeyCreationResult *creationResult) override {
        std::vector<uint8_t> unwrappedWrappingKeyBlob;
        const auto blobState = unwrapMetadataKeyBlob(wrappingKeyBlob, &unwrappedWrappingKeyBlob);
        if (blobState == MetadataKeyBlobState::UNWRAPPED) {
            return AndroidKeyMintDevice::importWrappedKey(wrappedKeyData, wrappingKeyBlob,
                                                          maskingKey, unwrappingParams, passwordSid,
                                                          biometricSid, creationResult);
        }
        if (blobState == MetadataKeyBlobState::MALFORMED)
            return invalidWrappedMetadataKey();
        std::vector<KeyParameter> normalizedParams = unwrappingParams;
        if (!hashMetadataAppId(&normalizedParams))
            return invalidWrappedMetadataKey();
        return AndroidKeyMintDevice::importWrappedKey(wrappedKeyData, unwrappedWrappingKeyBlob,
                                                      maskingKey, normalizedParams, passwordSid,
                                                      biometricSid, creationResult);
    }
};

template <typename T, class... Args>
std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> ser = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/default";
    LOG(INFO) << "adding rockchip keymint service instance: " << instanceName;
    binder_status_t status =
            AServiceManager_addService(ser->asBinder().get(), instanceName.c_str());
    CHECK_EQ(status, STATUS_OK);
    return ser;
}

int main() {
    // Zero threads seems like a useless pool, but below we'll join this thread to it, increasing
    // the pool size to 1.
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    // Add Keymint Service
    std::shared_ptr<AndroidKeyMintDevice> keyMint =
            addService<RockchipKeyMintDevice>(SecurityLevel::TRUSTED_ENVIRONMENT);
    // Add Secure Clock Service
    addService<AndroidSecureClock>(keyMint);
    // Add Shared Secret Service
    addService<AndroidSharedSecret>(keyMint);
    // Add Remotely Provisioned Component Service
    addService<AndroidRemotelyProvisionedComponentDevice>(keyMint);
    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
