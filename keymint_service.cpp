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

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include "AndroidKeyMintDevice.h"
#include "AndroidRemotelyProvisionedComponentDevice.h"
#include "AndroidSecureClock.h"
#include "AndroidSharedSecret.h"
#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <keymaster/soft_keymaster_logger.h>

using aidl::android::hardware::security::keymint::AndroidKeyMintDevice;
using aidl::android::hardware::security::keymint::AndroidRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::keymint::AttestationKey;
using aidl::android::hardware::security::keymint::ErrorCode;
using aidl::android::hardware::security::keymint::KeyCreationResult;
using aidl::android::hardware::security::keymint::KeyParameter;
using aidl::android::hardware::security::keymint::SecurityLevel;
using aidl::android::hardware::security::keymint::Tag;
using aidl::android::hardware::security::secureclock::AndroidSecureClock;
using aidl::android::hardware::security::sharedsecret::AndroidSharedSecret;

// The Rockchip KeyMaster stack aborts inside the prebuilt TEE libraries when a
// rollback-resistant key is requested, which kills this service during the
// first-boot metadata-encryption key generation and boots the device into
// recovery (init_user0_failed). Reject the tag before it reaches the TEE so
// keystore2/vold can fall back to a non-rollback-resistant key, the fallback
// vold already logs as expected (system/vold/KeyStorage.cpp).
class RockchipKeyMintDevice : public AndroidKeyMintDevice {
  public:
    explicit RockchipKeyMintDevice(SecurityLevel securityLevel)
        : AndroidKeyMintDevice(securityLevel) {}

    ndk::ScopedAStatus generateKey(const std::vector<KeyParameter>& keyParams,
                                   const std::optional<AttestationKey>& attestationKey,
                                   KeyCreationResult* creationResult) override {
        for (const auto& param : keyParams) {
            if (param.tag == Tag::ROLLBACK_RESISTANCE) {
                LOG(WARNING) << "rejecting rollback-resistant key generation before TEE";
                return ndk::ScopedAStatus::fromServiceSpecificError(
                        static_cast<int32_t>(ErrorCode::UNSUPPORTED_TAG));
            }
        }
        return AndroidKeyMintDevice::generateKey(keyParams, attestationKey, creationResult);
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
