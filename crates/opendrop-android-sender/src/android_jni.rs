//! JNI port: the ONLY production signer is AndroidKeyStore via Kotlin Java
//! Security APIs. No software/private-file key, network-driven UI approval,
//! or direct default-network socket exists in this module.
#![cfg(target_os = "android")]

use crate::recovery::{recover_committed, PendingRecovery};
use crate::sender::{connect_guest, prehash_source, prepare_offer};
use crate::{Result, SendError};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};
use opendrop_core::guest_tls::{LocalGuestIdentity, NativeP256Signer};
use opendrop_core::identity::DeviceId;
use opendrop_core::Error;
use std::cell::RefCell;
use std::ffi::{c_char, CStr};
use std::io::{self, Read};
use std::net::TcpStream;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// Exactly one foreground transfer/recovery operation per Android process.
// A genuine Activity Cancel/onStop calls the JNI cancellation symbol, which
// revokes Rust's per-session flag even when the Java Socket's fd was dup()ed.
static ACTIVE: OnceLock<Mutex<Option<Arc<AtomicBool>>>> = OnceLock::new();

struct ActiveSession(Arc<AtomicBool>);
impl ActiveSession {
    fn begin() -> Result<Self> {
        let mut state = ACTIVE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .map_err(|_| SendError::Protocol("Android session lock"))?;
        if state.is_some() {
            return Err(SendError::Protocol(
                "another guest operation is still active",
            ));
        }
        let active = Arc::new(AtomicBool::new(true));
        *state = Some(active.clone());
        Ok(Self(active))
    }
}
impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
        if let Ok(mut state) = ACTIVE.get_or_init(|| Mutex::new(None)).lock() {
            if state
                .as_ref()
                .is_some_and(|value| Arc::ptr_eq(value, &self.0))
            {
                *state = None;
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_opendrop_app_GuestNative_cancel(_env: JNIEnv, _receiver: JClass) {
    if let Ok(state) = ACTIVE.get_or_init(|| Mutex::new(None)).lock() {
        if let Some(active) = state.as_ref() {
            active.store(false, Ordering::Release);
        }
    }
}

#[derive(Clone)]
struct AndroidPort {
    vm: Arc<JavaVM>,
    bridge: GlobalRef,
}

impl AndroidPort {
    fn new(env: &mut JNIEnv, bridge: JObject) -> Result<Self> {
        Ok(Self {
            vm: Arc::new(
                env.get_java_vm()
                    .map_err(|_| SendError::Protocol("JNI VM unavailable"))?,
            ),
            bridge: env
                .new_global_ref(bridge)
                .map_err(|_| SendError::Protocol("JNI bridge unavailable"))?,
        })
    }

    fn bytes(&self, method: &str, argument: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| SendError::Protocol("JNI attach"))?;
        let value = if let Some(input) = argument {
            let arr = env
                .byte_array_from_slice(input)
                .map_err(|_| SendError::Protocol("JNI array"))?;
            env.call_method(
                self.bridge.as_obj(),
                method,
                "([B)[B",
                &[JValue::Object(&arr)],
            )
        } else {
            env.call_method(self.bridge.as_obj(), method, "()[B", &[])
        };
        let value = value.map_err(|_| {
            let _ = env.exception_clear();
            SendError::Protocol("Android protected-key operation failed")
        })?;
        let value = value
            .l()
            .map_err(|_| SendError::Protocol("JNI protected bytes"))?;
        if value.is_null() {
            return Err(SendError::Protocol(
                "Android protected-key operation unavailable",
            ));
        }
        env.convert_byte_array(JByteArray::from(value))
            .map_err(|_| SendError::Protocol("JNI byte array"))
    }

    fn open_network(&self, host: &str, port: i32) -> Result<TcpStream> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| SendError::Protocol("JNI attach"))?;
        let address = env
            .new_string(host)
            .map_err(|_| SendError::Protocol("JNI LAN address"))?;
        let descriptor = env
            .call_method(
                self.bridge.as_obj(),
                "openLanSocket",
                "(Ljava/lang/String;I)I",
                &[JValue::Object(&JObject::from(address)), JValue::Int(port)],
            )
            .map_err(|_| {
                let _ = env.exception_clear();
                SendError::Protocol("Android rejected LAN route or socket")
            })?
            .i()
            .map_err(|_| SendError::Protocol("invalid LAN descriptor"))?;
        if descriptor < 0 {
            return Err(SendError::Protocol("invalid Android network descriptor"));
        }
        // Kotlin passes a dup()ed fd detached from ParcelFileDescriptor,
        // transferring sole ownership of this descriptor to TcpStream.
        let socket = unsafe { TcpStream::from_raw_fd(descriptor) };
        socket.set_read_timeout(Some(std::time::Duration::from_millis(250)))?;
        socket.set_write_timeout(Some(std::time::Duration::from_millis(250)))?;
        Ok(socket)
    }

    fn open_source(&self, index: i32) -> Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| SendError::Protocol("JNI attach"))?;
        env.call_method(
            self.bridge.as_obj(),
            "openSource",
            "(I)V",
            &[JValue::Int(index)],
        )
        .map_err(|_| {
            let _ = env.exception_clear();
            SendError::Protocol("Android content URI grant revoked or source unavailable")
        })?;
        Ok(())
    }

    fn close_source(&self) {
        if let Ok(mut env) = self.vm.attach_current_thread() {
            if env
                .call_method(self.bridge.as_obj(), "closeSource", "()V", &[])
                .is_err()
            {
                let _ = env.exception_clear();
            }
        }
    }

    fn read_source(&self, len: usize) -> io::Result<Vec<u8>> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("JNI attach"))?;
        let value = env
            .call_method(
                self.bridge.as_obj(),
                "sourceChunk",
                "(I)[B",
                &[JValue::Int(len as i32)],
            )
            .map_err(|_| {
                let _ = env.exception_clear();
                io::Error::new(io::ErrorKind::PermissionDenied, "content URI grant lost")
            })?
            .l()
            .map_err(|_| io::Error::other("JNI read"))?;
        if value.is_null() {
            return Ok(Vec::new());
        }
        let bytes = env
            .convert_byte_array(JByteArray::from(value))
            .map_err(|_| io::Error::other("JNI source bytes"))?;
        if bytes.is_empty() || bytes.len() > len {
            return Err(io::Error::other(
                "content provider violated bounded read contract",
            ));
        }
        Ok(bytes)
    }

    fn device_id(&self) -> Result<DeviceId> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| SendError::Protocol("JNI attach"))?;
        let raw = env
            .call_method(
                self.bridge.as_obj(),
                "installationId",
                "()Ljava/lang/String;",
                &[],
            )
            .map_err(|_| {
                let _ = env.exception_clear();
                SendError::Protocol("Android installation ID unavailable")
            })?
            .l()
            .map_err(|_| SendError::Protocol("Android installation ID"))?;
        let id: String = env
            .get_string(&JString::from(raw))
            .map_err(|_| SendError::Protocol("Android installation ID UTF-8"))?
            .into();
        Ok(DeviceId::parse(&id)?)
    }

    fn persist_recovery(&self, record: &PendingRecovery) -> Result<()> {
        let mut plaintext = record.encode_for_android_keystore()?;
        let result = (|| -> Result<()> {
            let mut env = self
                .vm
                .attach_current_thread()
                .map_err(|_| SendError::Protocol("JNI attach"))?;
            let id = env
                .new_string(record.transfer_id().as_str())
                .map_err(|_| SendError::Protocol("JNI recovery ID"))?;
            let bytes = env
                .byte_array_from_slice(&plaintext)
                .map_err(|_| SendError::Protocol("JNI recovery bytes"))?;
            let accepted = env
                .call_method(
                    self.bridge.as_obj(),
                    "sealRecovery",
                    "(Ljava/lang/String;J[B)Z",
                    &[
                        JValue::Object(&JObject::from(id)),
                        JValue::Long(record.expires_ms() as jlong),
                        JValue::Object(&JObject::from(bytes)),
                    ],
                )
                .map_err(|_| {
                    let _ = env.exception_clear();
                    SendError::Protocol("protected recovery persistence unavailable")
                })?
                .z()
                .map_err(|_| SendError::Protocol("recovery persisted outcome"))?;
            if !accepted {
                return Err(SendError::Protocol("recovery not durably sealed"));
            }
            Ok(())
        })();
        plaintext.fill(0);
        result
    }

    fn read_recovery(&self, id: &str) -> Result<Vec<u8>> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| SendError::Protocol("JNI attach"))?;
        let id = env
            .new_string(id)
            .map_err(|_| SendError::Protocol("JNI recovery ID"))?;
        let output = env
            .call_method(
                self.bridge.as_obj(),
                "unsealRecovery",
                "(Ljava/lang/String;)[B",
                &[JValue::Object(&JObject::from(id))],
            )
            .map_err(|_| {
                let _ = env.exception_clear();
                SendError::Protocol("recovery unavailable, expired or protected key invalid")
            })?
            .l()
            .map_err(|_| SendError::Protocol("JNI recovery record"))?;
        if output.is_null() {
            return Err(SendError::Protocol("no pending recovery"));
        }
        let array = JByteArray::from(output);
        let bytes = env
            .convert_byte_array(&array)
            .map_err(|_| SendError::Protocol("JNI recovery bytes"))?;
        // JNI hands Rust a private copy. Wipe the decrypted Java byte array
        // rather than leaving a second credential in heap memory until GC.
        let zeros = vec![0i8; bytes.len()];
        env.set_byte_array_region(&array, 0, &zeros)
            .map_err(|_| SendError::Protocol("JNI recovery plaintext wipe failed"))?;
        Ok(bytes)
    }

    fn finish_recovery(&self, id: &str) -> Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| SendError::Protocol("JNI attach"))?;
        let id = env
            .new_string(id)
            .map_err(|_| SendError::Protocol("JNI recovery ID"))?;
        let success = env
            .call_method(
                self.bridge.as_obj(),
                "clearRecovery",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&JObject::from(id))],
            )
            .map_err(|_| {
                let _ = env.exception_clear();
                SendError::Protocol("recovery cleanup unavailable")
            })?
            .z()
            .map_err(|_| SendError::Protocol("recovery cleanup outcome"))?;
        if !success {
            return Err(SendError::Protocol("recovery cleanup not persisted"));
        }
        Ok(())
    }
}

/// The native port never generates or serializes a private key; every
/// signature request reaches the AndroidKeyStore nonexportable key handle.
struct KeystoreSigner(AndroidPort);
impl std::fmt::Debug for KeystoreSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AndroidKeyStore P256 signer (private key never exported)")
    }
}
impl NativeP256Signer for KeystoreSigner {
    fn canonical_public_spki_der(&self) -> std::result::Result<Vec<u8>, Error> {
        self.0
            .bytes("publicSpki", None)
            .map_err(|_| Error::Unauthorized)
    }
    fn sign_ecdsa_p256_sha256_der(&self, message: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        self.0
            .bytes("signP256Sha256", Some(message))
            .map_err(|_| Error::Unauthorized)
    }
}

struct UriStream {
    port: AndroidPort,
    extra: Vec<u8>,
}
impl UriStream {
    fn open(port: &AndroidPort, index: i32) -> Result<Self> {
        port.open_source(index)?;
        Ok(Self {
            port: port.clone(),
            extra: Vec::new(),
        })
    }
}
impl Read for UriStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if !self.extra.is_empty() {
            let count = output.len().min(self.extra.len());
            output[..count].copy_from_slice(&self.extra[..count]);
            self.extra.drain(..count);
            return Ok(count);
        }
        let data = self.port.read_source(output.len().min(32 * 1024))?;
        let count = data.len().min(output.len());
        output[..count].copy_from_slice(&data[..count]);
        self.extra.extend_from_slice(&data[count..]);
        Ok(count)
    }
}
impl Drop for UriStream {
    fn drop(&mut self) {
        self.port.close_source();
    }
}

thread_local! {
    static OWNER_UI: RefCell<Option<AndroidPort>> = const { RefCell::new(None) };
}
struct OwnerScope;
impl OwnerScope {
    fn enter(port: AndroidPort) -> Self {
        OWNER_UI.with(|slot| *slot.borrow_mut() = Some(port));
        Self
    }
}
impl Drop for OwnerScope {
    fn drop(&mut self) {
        OWNER_UI.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Called only by the shared security core on this worker's in-process
/// Activity bridge, never from a network callback or caller-supplied bool.
#[no_mangle]
pub extern "C" fn opendrop_android_owner_confirm_sas(
    code: *const c_char,
    fingerprint: *const c_char,
) -> i32 {
    if code.is_null() || fingerprint.is_null() {
        return 0;
    }
    let (Ok(code), Ok(fingerprint)) = (
        unsafe { CStr::from_ptr(code) }.to_str(),
        unsafe { CStr::from_ptr(fingerprint) }.to_str(),
    ) else {
        return 0;
    };
    if code.len() != 11 || fingerprint.len() != 64 {
        return 0;
    }
    OWNER_UI.with(|slot| {
        let owned = slot.borrow();
        let Some(port) = owned.as_ref() else {
            return 0;
        };
        let Ok(mut env) = port.vm.attach_current_thread() else {
            return 0;
        };
        let Ok(code) = env.new_string(code) else {
            return 0;
        };
        let Ok(fingerprint) = env.new_string(fingerprint) else {
            return 0;
        };
        let output = env.call_method(
            port.bridge.as_obj(),
            "confirmSas",
            "(Ljava/lang/String;Ljava/lang/String;)Z",
            &[
                JValue::Object(&JObject::from(code)),
                JValue::Object(&JObject::from(fingerprint)),
            ],
        );
        match output {
            Ok(value) => {
                if value.z().unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            Err(_) => {
                let _ = env.exception_clear();
                0
            }
        }
    })
}

fn build_identity(port: &AndroidPort) -> Result<LocalGuestIdentity> {
    Ok(LocalGuestIdentity::from_platform_signer(
        port.device_id()?,
        Arc::new(KeystoreSigner(port.clone())),
    )?)
}

/// Runtime probe available in the normal APK, not a fake-key hook. It
/// exercises the actual Java AndroidKeyStore private signing operation,
/// the shared Rust NativeP256Signer adapter and ring's P-256 DER verifier.
/// Returns only the SHA256 of the *public* canonical SPKI.
#[no_mangle]
pub extern "system" fn Java_org_opendrop_app_GuestNative_identitySelfTest(
    mut env: JNIEnv,
    _receiver: JClass,
    bridge: JObject,
) -> jstring {
    let result = (|| -> Result<String> {
        let port = AndroidPort::new(&mut env, bridge)?;
        let identity = build_identity(&port)?;
        Ok(identity.public_key().fingerprint().to_hex())
    })();
    let message =
        result.unwrap_or_else(|_| "ERROR: AndroidKeyStore P-256 identity unavailable".to_owned());
    env.new_string(message)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn send_one(
    port: &AndroidPort,
    index: jint,
    name: &str,
    size: jlong,
    host: &str,
    tcp_port: jint,
    active: Arc<AtomicBool>,
) -> Result<String> {
    let identity = build_identity(port)?;
    let (length, digest) = {
        let mut input = UriStream::open(port, index)?;
        prehash_source(&mut input, (size >= 0).then_some(size as u64))?
    };
    let offered = prepare_offer(&identity, name, length, digest)?;
    let socket = port.open_network(host, tcp_port)?;
    let pairing = connect_guest(socket, &identity, active)?;
    let _ui = OwnerScope::enter(port.clone());
    let authenticated = pairing.confirm_in_android_owner_ui()?;
    let mut source = UriStream::open(port, index)?;
    let receipt = authenticated.send_one(&offered, &mut source, |record| {
        port.persist_recovery(record)
    })?;
    drop(source);
    port.finish_recovery(offered.id().as_str())?;
    Ok(format!("OK:{}", receipt.transfer_id.as_str()))
}

fn recover_one(
    port: &AndroidPort,
    id: &str,
    host: &str,
    tcp_port: jint,
    active: Arc<AtomicBool>,
) -> Result<String> {
    let identity = build_identity(port)?;
    let mut data = port.read_recovery(id)?;
    let record = PendingRecovery::decode_from_android_keystore(&data);
    data.fill(0);
    let record = record?;
    if record.transfer_id().as_str() != id {
        return Err(SendError::Protocol("wrong recovery record ID"));
    }
    let socket = port.open_network(host, tcp_port)?;
    let receipt = recover_committed(socket, &identity, &record, active)?;
    port.finish_recovery(id)?;
    Ok(format!("RECOVERED:{}", receipt.transfer_id.as_str()))
}

fn reply(env: &mut JNIEnv, result: Result<String>) -> jstring {
    let message = match result {
        Ok(success) => success,
        Err(SendError::UncertainCompletion) => {
            "PENDING: receipt unknown; use Recover (do not resend)".to_owned()
        }
        Err(SendError::Rejected) => "REJECTED: the receiver declined or cancelled".to_owned(),
        Err(SendError::Cancelled) => "CANCELLED: foreground session stopped".to_owned(),
        Err(_) => "ERROR: transfer or recovery failed safely; no success claimed".to_owned(),
    };
    env.new_string(message)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_opendrop_app_GuestNative_sendOne(
    mut env: JNIEnv,
    _receiver: JClass,
    bridge: JObject,
    index: jint,
    name: JString,
    declared_size: jlong,
    host: JString,
    port: jint,
) -> jstring {
    let result = (|| -> Result<String> {
        let active = ActiveSession::begin()?;
        let name: String = env
            .get_string(&name)
            .map_err(|_| SendError::Protocol("JNI file name"))?
            .into();
        let host: String = env
            .get_string(&host)
            .map_err(|_| SendError::Protocol("JNI host"))?
            .into();
        let bridge = AndroidPort::new(&mut env, bridge)?;
        send_one(
            &bridge,
            index,
            &name,
            declared_size,
            &host,
            port,
            active.0.clone(),
        )
    })();
    reply(&mut env, result)
}

#[no_mangle]
pub extern "system" fn Java_org_opendrop_app_GuestNative_recoverOne(
    mut env: JNIEnv,
    _receiver: JClass,
    bridge: JObject,
    id: JString,
    host: JString,
    port: jint,
) -> jstring {
    let result = (|| -> Result<String> {
        let active = ActiveSession::begin()?;
        let id: String = env
            .get_string(&id)
            .map_err(|_| SendError::Protocol("JNI recovery ID"))?
            .into();
        let host: String = env
            .get_string(&host)
            .map_err(|_| SendError::Protocol("JNI host"))?
            .into();
        let bridge = AndroidPort::new(&mut env, bridge)?;
        recover_one(&bridge, &id, &host, port, active.0.clone())
    })();
    reply(&mut env, result)
}
