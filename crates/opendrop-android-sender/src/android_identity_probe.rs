//! The ONE production JNI P256 identity proof used by both network-enabled
//! Android and the networkless owner-installed smoke variant. The real
//! AndroidKeyStore supplies every signature; the shared core checks the
//! canonical public SPKI and signs a fixed challenge through the portable
//! NativeP256Signer contract, using ring to verify the DER ECDSA proof.
#![cfg(target_os = "android")]

use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::jstring;
use jni::{JNIEnv, JavaVM};
use opendrop_core::guest_tls::{LocalGuestIdentity, NativeP256Signer};
use opendrop_core::identity::DeviceId;
use opendrop_core::Error;
use std::sync::Arc;

struct AndroidKeystoreProof {
    vm: JavaVM,
    bridge: GlobalRef,
}

impl AndroidKeystoreProof {
    fn byte_method(&self, method: &str, value: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| Error::Unauthorized)?;
        let output = if let Some(message) = value {
            let arg = env
                .byte_array_from_slice(message)
                .map_err(|_| Error::Unauthorized)?;
            env.call_method(
                self.bridge.as_obj(),
                method,
                "([B)[B",
                &[JValue::Object(&arg)],
            )
        } else {
            env.call_method(self.bridge.as_obj(), method, "()[B", &[])
        };
        let bytes = output
            .map_err(|_| {
                let _ = env.exception_clear();
                Error::Unauthorized
            })?
            .l()
            .map_err(|_| Error::Unauthorized)?;
        if bytes.is_null() {
            return Err(Error::Unauthorized);
        }
        env.convert_byte_array(JByteArray::from(bytes))
            .map_err(|_| Error::Unauthorized)
    }

    fn device(&self) -> Result<DeviceId, Error> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| Error::Unauthorized)?;
        let object = env
            .call_method(
                self.bridge.as_obj(),
                "installationId",
                "()Ljava/lang/String;",
                &[],
            )
            .map_err(|_| {
                let _ = env.exception_clear();
                Error::Unauthorized
            })?
            .l()
            .map_err(|_| Error::Unauthorized)?;
        let text: String = env
            .get_string(&JString::from(object))
            .map_err(|_| Error::Unauthorized)?
            .into();
        DeviceId::parse(&text)
    }
}

impl std::fmt::Debug for AndroidKeystoreProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("production AndroidKeyStore signer, no private export")
    }
}

impl NativeP256Signer for AndroidKeystoreProof {
    fn canonical_public_spki_der(&self) -> Result<Vec<u8>, Error> {
        self.byte_method("publicSpki", None)
    }
    fn sign_ecdsa_p256_sha256_der(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.byte_method("signP256Sha256", Some(message))
    }
}

/// Same JNI symbol/API as S1-E; never generated from software test keys.
/// Returns only the SHA256 fingerprint of the verified PUBLIC key.
#[no_mangle]
pub extern "system" fn Java_org_opendrop_app_GuestNative_identitySelfTest(
    mut env: JNIEnv,
    _class: JClass,
    bridge: JObject,
) -> jstring {
    let verified = (|| -> Result<String, Error> {
        let signer = Arc::new(AndroidKeystoreProof {
            vm: env.get_java_vm().map_err(|_| Error::Unauthorized)?,
            bridge: env
                .new_global_ref(bridge)
                .map_err(|_| Error::Unauthorized)?,
        });
        let device = signer.device()?;
        let identity = LocalGuestIdentity::from_platform_signer(device, signer)?;
        Ok(identity.public_key().fingerprint().to_hex())
    })();
    let response =
        verified.unwrap_or_else(|_| "ERROR: AndroidKeyStore P256 proof unavailable".to_string());
    env.new_string(response)
        .map(|output| output.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
