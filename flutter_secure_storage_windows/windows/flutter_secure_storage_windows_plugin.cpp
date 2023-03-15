#include "include/flutter_secure_storage_windows/flutter_secure_storage_windows_plugin.h"

// This must be included before many other Windows headers.
#include <ShlObj_core.h>
#include <atlstr.h>
#include <bcrypt.h>
#include <direct.h>
#include <errno.h>
#include <sys/stat.h>
#include <wincred.h>
#include <windows.h>
#include <winternl.h>

// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {

class FlutterSecureStorageWindowsPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  FlutterSecureStorageWindowsPlugin();

  virtual ~FlutterSecureStorageWindowsPlugin();

 private:
  /// <summary>
  /// Called when a method is called on this plugin's channel from Dart.
  /// </summary>
  /// <param name="method_call"><see cref="flutter::MethodCall" /> to contains
  /// method call information and its arguments.</param>
  /// <param name="result"><see cref="std::unique_ptr"/> of <see
  /// cref="flutter::MethodResult" /> to store method invocation result.</param>
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  /// <summary>
  /// Retrieves the value passed to the given param.
  /// </summary>
  /// <param name="param">A name of the parameter.</param>
  /// <param name="args">Arguments gotten from <see cref="flutter::MethodCall"
  /// />.</param> <returns> <see cref="std::optional" />, which stores the
  /// argument value when <paramref name="args" /> contains an entry with
  /// <paramref name="param"/>; otherwise, <see cref="std::nullopt" />.
  /// </returns>
  std::optional<std::string> GetStringArg(const std::string& param,
                                          const flutter::EncodableMap* args);

  /// <summary>
  /// Derives the key for a value given a method argument map.
  /// </summary>
  /// <param name="args">Arguments gotten from <see cref="flutter::MethodCall"
  /// />.</param>
  /// <returns> <see cref="std::optional" />, which stores the
  /// derived key for a value <paramref name="args" /> contains an entry with
  /// <paramref name="param"/>; otherwise, <see cref="std::nullopt" />.
  /// </returns>
  std::optional<std::string> FlutterSecureStorageWindowsPlugin::GetValueKey(
      const flutter::EncodableMap* args);

  /// <summary>
  /// <para>Removes prefix of the given storage key.</para>
  /// <para>The prefix (defined by <c>ELEMENT_PREFERENCES_KEY_PREFIX</c>) is
  /// added automatically when writing to storage, to distinguish values that
  /// are written by this plugin from values that are not.</para>
  /// </summary>
  /// <param name="key">An original stored key with prefix.</param>
  /// <returns>A key without prefix.</returns>
  std::string RemoveKeyPrefix(const std::string& key);

  /// <summary>
  /// Handles Win32 error. When this method completes, <c>result->Error</c> is
  /// called.
  /// </summary>
  /// <param name="operation">A name of operation. Generally,
  /// "CALLER_METHOD->TARGET_FUNCTION" format.</param>
  /// <param name="error">A Win32 error code.</param>
  /// <param name="result"><see cref="std::unique_ptr"/>
  /// of <see cref="flutter::MethodResult" /> to store method invocation
  /// result.</param>
  void FlutterSecureStorageWindowsPlugin::HandleWin32Error(
      const WCHAR* operation, const DWORD error,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Handles NTSTATUS error. When this method completes, <c>result->Error</c>
  /// is called.
  /// </summary>
  /// <param name="operation">A name of operation. Generally,
  /// "CALLER_METHOD->TARGET_FUNCTION" format.</param>
  /// <param name="error">A NTSTATUS error code.</param>
  /// <param name="result"><see cref="std::unique_ptr"/>
  /// of <see cref="flutter::MethodResult" /> to store method invocation
  /// result.</param>
  void FlutterSecureStorageWindowsPlugin::HandleNTStatus(
      const WCHAR* operation, const NTSTATUS error,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Converts specified UTF-16 based string (<see cref="std::wstring" />) to
  /// UTF-8 based string (<see cref="std::string" />).
  /// </summary>
  /// <param name="utf16">A<see cref="std::wstring" />.</param>
  /// <returns>A <see cref="std::string" /> which contains UTF-8 encoded
  /// string.</returns>
  std::string FlutterSecureStorageWindowsPlugin::ConvertToUtf8(
      std::wstring utf16);

  /// <summary>
  /// Gets an appliction support path to store encrypted data.
  /// </summary>
  /// <param name="path">When success, a path will be stored.</param>
  /// <param name="result"><see cref="std::unique_ptr"/>
  /// of <see cref="flutter::MethodResult" /> to store method invocation
  /// result. When returns <c>false</c>, <c>result->Error</c> will be
  /// called.</param>
  /// <returns><c>true</c>, when the path exists; <c>false</c>, otherwise.
  /// Note that the path will be deleted until you get a file handle for the
  /// path or descendant file system entries.
  /// </returns>
  bool GetApplicationSupportPath(
      std::wstring& path,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Sanitizes directory path.
  /// </summary>
  /// <param name="string">An original path.</param>
  /// <returns>A sanitized path.</returns>
  std::wstring SanitizeDirString(std::wstring string);

  /// <summary>
  /// Makes specified directory.
  /// </summary>
  /// <param name="path">A path of directory.</param>
  /// <returns>Win32 error code. <see cref="ERROR_SUCCESS" /> indicates
  /// success.</returns>
  DWORD MakePath(const std::wstring& path);

  /// <summary>
  /// Gets a new encryption key for current user.
  /// </summary>
  /// <param name="result"><see cref="std::unique_ptr"/>
  /// of <see cref="flutter::MethodResult" /> to store method invocation
  /// result. When returns <c>NULL</c>, <c>result->Error</c> will be
  /// called.</param>
  /// <returns>A pointer to the key. This value must be freed with <see
  /// cref="HeapFree" /> function. <c>NULL</c> when fails.</returns>
  PBYTE GetEncryptionKey(
      HANDLE heapHandle,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Stores the given value under the given key.
  /// </summary>
  /// <param name="key">A key.</param>
  /// <param name="val">A value, which is encoded with UTF-8 according to
  /// <c>StandardMessageCodec</c>.</param>
  /// <param name="result"><see cref="std::unique_ptr"/> of <see
  /// cref="flutter::MethodResult" /> to store method invocation result. When
  /// returns, <c>result->Success</c> or <c>result->Error</c> will be
  /// called.</param>
  void Write(
      const std::string& key, const std::string& val,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Read value and return it. <strong>Note that this method does not call
  /// MethodResult->Success().</strong>
  /// </summary>
  /// <param name="key"> A key to read.</param>
  /// <param name="result"><see cref="std::unique_ptr"/> of <see
  /// cref="flutter::MethodResult" /> to store method invocation result. When
  /// returns <see cref="std::nullopt" />, <c>result->Error</c> will be
  /// called.</param>
  /// <returns> <see cref="std::optional" />, which stores the
  /// read value for <paramref name="key" />; otherwise, <see
  /// cref="std::nullopt" />.
  /// </returns>
  std::optional<std::string> Read(
      const std::string& key,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Reads all stored key-values pairs.
  /// </summary>
  /// <param name="result"><see cref="std::unique_ptr"/> of <see
  /// cref="flutter::MethodResult" /> to store method invocation result. When
  /// returns, <c>result->Success</c> or <c>result->Error</c> will be
  /// called.</param>
  void ReadAll(
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Deletes the given key value pair.
  /// </summary>
  /// <param name="key">A key.</param>
  /// <param name="result"><see cref="std::unique_ptr"/> of <see
  /// cref="flutter::MethodResult" /> to store method invocation result. When
  /// returns, <c>result->Success</c> or <c>result->Error</c> will be
  /// called.</param>
  void Delete(
      const std::string& key,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Deletes all stored key-value pairs.
  /// </summary>
  /// <param name="result"><see cref="std::unique_ptr"/> of <see
  /// cref="flutter::MethodResult" /> to store method invocation result. When
  /// returns, <c>result->Success</c> or <c>result->Error</c> will be
  /// called.</param>
  void DeleteAll(
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);

  /// <summary>
  /// Returns the value whether the given key and correponding value is stored
  /// or not.
  /// </summary>
  /// <param name="key">A key.</param>
  /// <param name="result"><see cref="std::unique_ptr"/> of <see
  /// cref="flutter::MethodResult" /> to store method invocation result. When
  /// returns, <c>result->Success</c> or <c>result->Error</c> will be
  /// called. If the entry exists, <c>true</c> will be stored. If the entry does
  /// not exist, <c>false</> will be stored. Otherwise, that is any error was
  /// occurred, the error will be stored with <c>result->Error()</c>.</param>
  void ContainsKey(
      const std::string& key,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result);
};

const std::string ELEMENT_PREFERENCES_KEY_PREFIX = SECURE_STORAGE_KEY_PREFIX;
const int ELEMENT_PREFERENCES_KEY_PREFIX_LENGTH =
    (sizeof SECURE_STORAGE_KEY_PREFIX) - 1;

// this string is used to filter the credential storage so that only the values
// written by this plugin shows up.
const CA2W CREDENTIAL_FILTER((ELEMENT_PREFERENCES_KEY_PREFIX + '*').c_str());

static inline void rtrim(std::wstring& s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](wchar_t ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

// static
void FlutterSecureStorageWindowsPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(),
          "plugins.it_nomads.com/flutter_secure_storage",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<FlutterSecureStorageWindowsPlugin>();

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto& call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

FlutterSecureStorageWindowsPlugin::FlutterSecureStorageWindowsPlugin() {}

FlutterSecureStorageWindowsPlugin::~FlutterSecureStorageWindowsPlugin() {}

std::optional<std::string> FlutterSecureStorageWindowsPlugin::GetValueKey(
    const flutter::EncodableMap* args) {
  auto key = this->GetStringArg("key", args);
  if (key.has_value()) return ELEMENT_PREFERENCES_KEY_PREFIX + key.value();
  return std::nullopt;
}

std::string FlutterSecureStorageWindowsPlugin::RemoveKeyPrefix(
    const std::string& key) {
  return key.substr(ELEMENT_PREFERENCES_KEY_PREFIX_LENGTH);
}

std::optional<std::string> FlutterSecureStorageWindowsPlugin::GetStringArg(
    const std::string& param, const flutter::EncodableMap* args) {
  auto p = args->find(param);
  if (p == args->end()) return std::nullopt;
  return std::get<std::string>(p->second);
}

void FlutterSecureStorageWindowsPlugin::HandleWin32Error(
    const WCHAR* operation, const DWORD error,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  std::ostringstream code;
  code << error;
  std::wostringstream message;
  LPVOID messageBuffer = NULL;
  message << operation << L", 0x" << std::hex << std::setw(8)
          << std::setfill(L'0') << error << L", ";
  auto charLength = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPWSTR)&messageBuffer, 0, NULL);
  if (0 == charLength) {
    std::wcerr << L"FormatMessageW failes for: 0x" << std::hex << std::setw(8)
               << std::setfill(L'0') << error << std::endl;
    return;
  }

  auto messageString =
      std::wstring(static_cast<wchar_t*>(messageBuffer), charLength);
  message << messageString;
  LocalFree(messageBuffer);
  result->Error(code.str(), this->ConvertToUtf8(message.str()));
}

void FlutterSecureStorageWindowsPlugin::HandleNTStatus(
    const WCHAR* operation, const NTSTATUS error,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  this->HandleWin32Error(operation, HRESULT_FROM_NT(error), result);
}

std::string FlutterSecureStorageWindowsPlugin::ConvertToUtf8(
    std::wstring utf16) {
  // Get length of UTF-8 sequence
  int utf8Length =
      WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, NULL, NULL);
  auto utf8Buffer = std::make_unique<char[]>(utf8Length);
  // Conversion
  WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, utf8Buffer.get(),
                      utf8Length, NULL, NULL);
  return std::string(utf8Buffer.get(), utf8Length);
}

bool FlutterSecureStorageWindowsPlugin::GetApplicationSupportPath(
    std::wstring& path,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  std::wstring companyName;
  std::wstring productName;
  WCHAR nameBuffer[MAX_PATH + 1]{};
  char* infoBuffer;
  DWORD versionInfoSize;
  DWORD resVal;
  UINT queryLen;
  LPVOID queryVal;
  LPWSTR appdataPath;
  std::wostringstream stream;

  auto hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, NULL,
                                 &appdataPath);
  if (FAILED(hr)) {
    HandleWin32Error(L"GetApplicationSupportPath->SHGetKnownFolderPath", hr,
                     result);
    return false;
  }

  resVal = GetModuleFileNameW(NULL, nameBuffer, MAX_PATH);
  if (resVal == 0) {
    HandleWin32Error(L"GetApplicationSupportPath->GetModuleFileName",
                     GetLastError(), result);
    return false;
  }

  versionInfoSize = GetFileVersionInfoSizeW(nameBuffer, NULL);
  if (versionInfoSize != 0) {
    infoBuffer = (char*)calloc(versionInfoSize, sizeof(char));
    if (NULL == infoBuffer) {
      HandleWin32Error(L"GetApplicationSupportPath->calloc", ERROR_OUTOFMEMORY,
                       result);
      return false;
    }
    if (GetFileVersionInfoW(nameBuffer, 0, versionInfoSize, infoBuffer) == 0) {
      free(infoBuffer);
      infoBuffer = NULL;
    } else {
      if (0 != VerQueryValueW(infoBuffer,
                              TEXT("\\StringFileInfo\\040904e4\\CompanyName"),
                              &queryVal, &queryLen)) {
        companyName = SanitizeDirString(std::wstring((const WCHAR*)queryVal));
      }
      if (0 != VerQueryValueW(infoBuffer,
                              TEXT("\\StringFileInfo\\040904e4\\ProductName"),
                              &queryVal, &queryLen)) {
        productName = SanitizeDirString(std::wstring((const WCHAR*)queryVal));
      }
    }
    stream << appdataPath << "\\" << companyName << "\\" << productName;
    path = stream.str();
  } else {
    HandleWin32Error(L"GetApplicationSupportPath->GetFileVersionInfoSize",
                     GetLastError(), result);
    return false;
  }

  return true;
}

std::wstring FlutterSecureStorageWindowsPlugin::SanitizeDirString(
    std::wstring string) {
  std::wstring sanitizedString =
      std::regex_replace(string, std::wregex(L"[<>:\"/\\\\|?*]"), L"_");
  rtrim(sanitizedString);
  sanitizedString =
      std::regex_replace(sanitizedString, std::wregex(L"[.]+$"), L"");
  return sanitizedString;
}

DWORD FlutterSecureStorageWindowsPlugin::MakePath(const std::wstring& path) {
  // TODO: Improve error handling
  while (1) {
    int ret = _wmkdir(path.c_str());
    if (ret == 0) {
      return ERROR_SUCCESS;
    }
    switch (errno) {
      case ENOENT: {
        size_t pos = path.find_last_of('/');
        if (pos == std::wstring::npos) pos = path.find_last_of('\\');
        if (pos == std::wstring::npos) return ERROR_PATH_NOT_FOUND;
        // Create parent
        ret = MakePath(path.substr(0, pos));
        if (ERROR_SUCCESS != ret) {
          return ERROR_PATH_NOT_FOUND;
        }
        // Retry
        continue;
      }
      case EEXIST:
        // We do not re-check here because path can be removed as long as we do
        // not hold handle.
        return ERROR_SUCCESS;
      default:
        return static_cast<DWORD>(E_FAIL);
    }
  }
}

PBYTE FlutterSecureStorageWindowsPlugin::GetEncryptionKey(
    HANDLE heapHandle,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  const size_t KEY_SIZE = 16;
  PBYTE AesKey;
  PCREDENTIALW pcred;
  CA2W target_name(("key_" + ELEMENT_PREFERENCES_KEY_PREFIX).c_str());

  AesKey = (PBYTE)HeapAlloc(heapHandle, 0, KEY_SIZE);
  if (NULL == AesKey) {
    HandleWin32Error(L"GetEncryptionKey->HeapAlloc", GetLastError(), result);
    return NULL;
  }

  if (CredReadW(target_name.m_psz, CRED_TYPE_GENERIC, 0, &pcred)) {
    if (pcred->CredentialBlobSize != KEY_SIZE) {
      CredFree(pcred);
      // Ignore error here.
      if (!CredDeleteW(target_name.m_psz, CRED_TYPE_GENERIC, 0)) {
        std::cerr << "GetEncryptionKey->CredDeleteW failed, 0x" << std::hex
                  << std::setw(8) << std::setfill('0') << GetLastError()
                  << std::endl;
      }
      goto NewKey;
    }
    memcpy(AesKey, pcred->CredentialBlob, KEY_SIZE);
    CredFree(pcred);
    return AesKey;
  }

  auto credError = GetLastError();
  if (ERROR_NOT_FOUND != credError) {
    HandleWin32Error(L"GetEncryptionKey->CredReadW", credError, result);
    return NULL;
  }
NewKey:
  auto bcryptError =
      BCryptGenRandom(NULL, AesKey, KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(bcryptError)) {
    HandleNTStatus(L"GetEncryptionKey->BCryptGenRandom", bcryptError, result);
    return NULL;
  }
  CREDENTIALW cred = {0};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = target_name.m_psz;
  cred.CredentialBlobSize = KEY_SIZE;
  cred.CredentialBlob = AesKey;
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

  if (!CredWriteW(&cred, 0)) {
    HandleWin32Error(L"GetEncryptionKey->CredWriteW", GetLastError(), result);
    return NULL;
  }
  return AesKey;
}

void FlutterSecureStorageWindowsPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  std::string method = method_call.method_name();
  const auto* args =
      std::get_if<flutter::EncodableMap>(method_call.arguments());

  if (method == "write") {
    auto key = this->GetValueKey(args);
    auto val = this->GetStringArg("value", args);
    if (key.has_value()) {
      if (val.has_value())
        this->Write(key.value(), val.value(), result);
      else
        this->Delete(key.value(), result);
    } else {
      HandleWin32Error(L"HandleMethodCall(write)", ERROR_INVALID_PARAMETER,
                       result);
    }
  } else if (method == "read") {
    auto key = this->GetValueKey(args);
    if (key.has_value()) {
      auto val = this->Read(key.value(), result);
      if (val.has_value()) {
        result->Success(flutter::EncodableValue(val.value()));
      }
    } else {
      HandleWin32Error(L"HandleMethodCall(read)", ERROR_INVALID_PARAMETER,
                       result);
    }
  } else if (method == "readAll") {
    this->ReadAll(result);
  } else if (method == "delete") {
    auto key = this->GetValueKey(args);
    if (key.has_value()) {
      this->Delete(key.value(), result);
    } else {
      HandleWin32Error(L"HandleMethodCall(delete)", ERROR_INVALID_PARAMETER,
                       result);
    }
  } else if (method == "deleteAll") {
    this->DeleteAll(result);
  } else if (method == "containsKey") {
    auto key = this->GetValueKey(args);
    if (key.has_value()) {
      this->ContainsKey(key.value(), result);
    } else {
      HandleWin32Error(L"HandleMethodCall(containsKey)",
                       ERROR_INVALID_PARAMETER, result);
    }
  } else {
    result->NotImplemented();
  }
}

void FlutterSecureStorageWindowsPlugin::Write(
    const std::string& key, const std::string& val,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  // The recommended size for AES-GCM IV is 12 bytes
  const DWORD NONCE_SIZE = 12;
  const DWORD KEY_SIZE = 16;

  BCRYPT_ALG_HANDLE algo = NULL;
  BCRYPT_KEY_HANDLE keyHandle = NULL;
  HANDLE heapHandle = INVALID_HANDLE_VALUE;
  DWORD bytesWritten = 0, ciphertextSize = 0;
  PBYTE ciphertext = NULL, iv = NULL, encryptionKey = NULL;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo{};
  BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths{};
  std::basic_ofstream<BYTE> fs;
  std::wstring appSupportPath;

  heapHandle = GetProcessHeap();
  if (INVALID_HANDLE_VALUE == heapHandle) {
    HandleWin32Error(L"Write->GetProcessHeap", GetLastError(), result);
    return;
  }

  iv = (PBYTE)HeapAlloc(heapHandle, 0, NONCE_SIZE);
  if (NULL == iv) {
    HandleWin32Error(L"Write->HeapAlloc(IV)", GetLastError(), result);
    goto cleanup;
  }

  encryptionKey = GetEncryptionKey(heapHandle, result);
  if (NULL == encryptionKey) {
    goto cleanup;
  }
  auto status =
      BCryptOpenAlgorithmProvider(&algo, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Write->BCryptOpenAlgorithmProvider", status, result);
    goto cleanup;
  }
  status = BCryptSetProperty(algo, BCRYPT_CHAINING_MODE,
                             (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                             sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Write->BCryptSetProperty", status, result);
    goto cleanup;
  }
  status = BCryptGetProperty(
      algo, BCRYPT_AUTH_TAG_LENGTH, (PBYTE)&authTagLengths,
      sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT), &bytesWritten, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Write->BCryptGetProperty", status, result);
    goto cleanup;
  }
  BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
  authInfo.pbNonce = (PUCHAR)HeapAlloc(heapHandle, 0, NONCE_SIZE);
  if (NULL == authInfo.pbNonce) {
    HandleWin32Error(L"Write->HeapAlloc(pbNonce)", GetLastError(), result);
    goto cleanup;
  }
  authInfo.cbNonce = NONCE_SIZE;
  status = BCryptGenRandom(NULL, iv, authInfo.cbNonce,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Write->BCryptGenRandom", status, result);
    goto cleanup;
  }
  // copy the original IV into the authInfo, we can't write the IV directly into
  // the authInfo because it will change after calling BCryptEncrypt and we
  // still need to write the IV to file
  memcpy(authInfo.pbNonce, iv, authInfo.cbNonce);
  // We do not use additional authenticated data
  authInfo.pbAuthData = NULL;
  authInfo.cbAuthData = 0;
  // Make space for the authentication tag
  authInfo.pbTag = (PUCHAR)HeapAlloc(heapHandle, 0, authTagLengths.dwMaxLength);
  if (NULL == authInfo.pbTag) {
    HandleWin32Error(L"Write->HeapAlloc(pbTag)", GetLastError(), result);
    goto cleanup;
  }
  authInfo.cbTag = authTagLengths.dwMaxLength;
  status = BCryptGenerateSymmetricKey(algo, &keyHandle, NULL, 0, encryptionKey,
                                      KEY_SIZE, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Write->BCryptGenerateSymmetricKey", status, result);
    goto cleanup;
  }
  // First call to BCryptEncrypt to get size of ciphertext
  status =
      BCryptEncrypt(keyHandle, (PUCHAR)val.c_str(), (ULONG)val.length() + 1,
                    (PVOID)&authInfo, NULL, 0, NULL, 0, &bytesWritten, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Write->BCryptEncrypt(1)", status, result);
    goto cleanup;
  }
  ciphertextSize = bytesWritten;
  ciphertext = (PBYTE)HeapAlloc(heapHandle, 0, ciphertextSize);
  if (ciphertext == NULL) {
    HandleWin32Error(L"Write->HeapAlloc(CipherText)", GetLastError(), result);
    goto cleanup;
  }
  // Actual encryption
  status = BCryptEncrypt(keyHandle, (PUCHAR)val.c_str(),
                         (ULONG)val.length() + 1, (PVOID)&authInfo, NULL, 0,
                         ciphertext, ciphertextSize, &bytesWritten, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Write->BCryptEncrypt(2)", status, result);
    goto cleanup;
  }
  if (!GetApplicationSupportPath(appSupportPath, result)) {
    goto cleanup;
  }
  auto ret = MakePath(appSupportPath);
  if (ERROR_SUCCESS != ret) {
    HandleWin32Error(L"Write->MakePath(appSupportPath)", ret, result);
    goto cleanup;
  }
  // TODO: sanitize
  // TODO: improve error handling
  fs = std::basic_ofstream<BYTE>(appSupportPath + L"\\" +
                                     std::wstring(key.begin(), key.end()) +
                                     L".secure",
                                 std::ios::binary | std::ios::trunc);
  if (!fs) {
    result->Error("Failed to open output stream");
    goto cleanup;
  }
  fs.write(iv, NONCE_SIZE);
  fs.write(authInfo.pbTag, authInfo.cbTag);
  fs.write(ciphertext, ciphertextSize);
  fs.close();
  result->Success();
cleanup:
  if (iv && INVALID_HANDLE_VALUE != heapHandle) {
    if (!HeapFree(heapHandle, 0, iv)) {
      std::cerr << "Write->HeapFree(iv) failed, 0x" << std::hex << std::setw(8)
                << std::setfill('0') << GetLastError() << std::endl;
    }
  }
  if (encryptionKey && INVALID_HANDLE_VALUE != heapHandle) {
    if (!HeapFree(heapHandle, 0, encryptionKey)) {
      std::cerr << "Write->HeapFree(encryptionKey) failed, 0x" << std::hex
                << std::setw(8) << std::setfill('0') << GetLastError()
                << std::endl;
    }
  }
  if (authInfo.pbNonce && INVALID_HANDLE_VALUE != heapHandle) {
    if (!HeapFree(heapHandle, 0, authInfo.pbNonce)) {
      std::cerr << "Write->HeapFree(pbNonce) failed, 0x" << std::hex
                << std::setw(8) << std::setfill('0') << GetLastError()
                << std::endl;
    }
  }
  if (authInfo.pbTag && INVALID_HANDLE_VALUE != heapHandle) {
    if (!HeapFree(heapHandle, 0, authInfo.pbTag)) {
      std::cerr << "Write->HeapFree(pbTag) failed, 0x" << std::hex
                << std::setw(8) << std::setfill('0') << GetLastError()
                << std::endl;
    }
  }
  if (ciphertext && INVALID_HANDLE_VALUE != heapHandle) {
    if (!HeapFree(heapHandle, 0, ciphertext)) {
      std::cerr << "Write->HeapFree(ciphertext) failed, 0x" << std::hex
                << std::setw(8) << std::setfill('0') << GetLastError()
                << std::endl;
    }
  }
  return;
}

std::optional<std::string> FlutterSecureStorageWindowsPlugin::Read(
    const std::string& key,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  const DWORD NONCE_SIZE = 12;
  const DWORD KEY_SIZE = 16;

  NTSTATUS status;
  BCRYPT_ALG_HANDLE algo = NULL;
  BCRYPT_KEY_HANDLE keyHandle = NULL;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo{};
  BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths{};

  HANDLE heapHandle = INVALID_HANDLE_VALUE;
  PBYTE encryptionKey = NULL, ciphertext = NULL, fileBuffer = NULL,
        plaintext = NULL;
  DWORD plaintextSize = 0, bytesWritten = 0, ciphertextSize = 0;
  std::wstring appSupportPath;
  std::basic_ifstream<BYTE> fs;
  std::streampos fileSize;
  std::optional<std::string> returnVal = std::nullopt;

  heapHandle = GetProcessHeap();
  if (INVALID_HANDLE_VALUE == heapHandle) {
    HandleWin32Error(L"Read->GetProcessHeap", GetLastError(), result);
    goto cleanup;
  }

  encryptionKey = GetEncryptionKey(heapHandle, result);
  if (NULL == encryptionKey) {
    goto cleanup;
  }
  if (!GetApplicationSupportPath(appSupportPath, result)) {
    goto cleanup;
  }
  auto ret = MakePath(appSupportPath);
  if (ERROR_SUCCESS != ret) {
    HandleWin32Error(L"Read->MakePath(appSupportPath)", ret, result);
    goto cleanup;
  }
  // TODO: sanitize
  // TODO: improve error handling
  // Read full file into a buffer
  fs = std::basic_ifstream<BYTE>(appSupportPath + L"\\" +
                                     std::wstring(key.begin(), key.end()) +
                                     L".secure",
                                 std::ios::binary);
  if (!fs.good()) {
    // Backwards comp.
    PCREDENTIALW pcred;
    // Key will be converted to wchar internally.
    CA2W target_name(key.c_str());
    bool ok = CredReadW(target_name.m_psz, CRED_TYPE_GENERIC, 0, &pcred);
    if (ok) {
      auto val = std::string((char*)pcred->CredentialBlob);
      CredFree(pcred);
      returnVal = val;
    } else {
      error = GetLastError();
      if (error != ERROR_NOT_FOUND) {
        HandleWin32Error(L"Read->CredReadW", error, result);
      }
    }
    goto cleanup;
  }
  fs.unsetf(std::ios::skipws);
  fs.seekg(0, std::ios::end);
  fileSize = fs.tellg();
  fs.seekg(0, std::ios::beg);

  fileBuffer = (PBYTE)HeapAlloc(heapHandle, 0, fileSize);
  if (NULL == fileBuffer) {
    HandleWin32Error(L"Read->HeapAlloc(file)", GetLastError(), result);
    goto cleanup;
  }
  fs.read(fileBuffer, fileSize);
  fs.close();

  status = BCryptOpenAlgorithmProvider(&algo, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Read->BCryptOpenAlgorithmProvider", status, result);
    goto cleanup;
  }
  status = BCryptSetProperty(algo, BCRYPT_CHAINING_MODE,
                             (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                             sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Read->BCryptSetProperty", status, result);
    goto cleanup;
  }
  status = BCryptGetProperty(
      algo, BCRYPT_AUTH_TAG_LENGTH, (PBYTE)&authTagLengths,
      sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT), &bytesWritten, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Read->BCryptGetProperty", status, result);
    goto cleanup;
  }

  BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
  authInfo.pbNonce = (PUCHAR)HeapAlloc(heapHandle, 0, NONCE_SIZE);
  if (NULL == authInfo.pbNonce) {
    HandleWin32Error(L"Read->HeapAlloc(pbNonce)", GetLastError(), result);
    goto cleanup;
  }
  authInfo.cbNonce = NONCE_SIZE;
  // Check if file is at least long enough for iv and authentication tag
  if (fileSize <=
      static_cast<long long>(NONCE_SIZE) + authTagLengths.dwMaxLength) {
    result->Error("File is too small.");
    goto cleanup;
  }
  authInfo.pbTag = (PUCHAR)HeapAlloc(heapHandle, 0, authTagLengths.dwMaxLength);
  if (NULL == authInfo.pbTag) {
    HandleWin32Error(L"Read->HeapAlloc(pbTag)", GetLastError(), result);
    goto cleanup;
  }
  ciphertextSize = (DWORD)fileSize - NONCE_SIZE - authTagLengths.dwMaxLength;
  ciphertext = (PBYTE)HeapAlloc(heapHandle, 0, ciphertextSize);
  if (NULL == ciphertext) {
    HandleWin32Error(L"Read->HeapAlloc(ciphertext)", GetLastError(), result);
    goto cleanup;
  }
  // Copy different parts needed for decryption from filebuffer
#pragma warning(push)
#pragma warning(disable : 6385)
  memcpy(authInfo.pbNonce, fileBuffer, NONCE_SIZE);
#pragma warning(pop)
  memcpy(authInfo.pbTag, &fileBuffer[NONCE_SIZE], authTagLengths.dwMaxLength);
  memcpy(ciphertext, &fileBuffer[NONCE_SIZE + authTagLengths.dwMaxLength],
         ciphertextSize);
  authInfo.cbTag = authTagLengths.dwMaxLength;

  status = BCryptGenerateSymmetricKey(algo, &keyHandle, NULL, 0, encryptionKey,
                                      KEY_SIZE, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Read->BCryptGenerateSymmetricKey", status, result);
    goto cleanup;
  }
  // First call is to determine size of plaintext
  status = BCryptDecrypt(keyHandle, ciphertext, ciphertextSize,
                         (PVOID)&authInfo, NULL, 0, NULL, 0, &bytesWritten, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Read->BCryptDecrypt(1)", status, result);
    goto cleanup;
  }
  plaintextSize = bytesWritten;
  plaintext = (PBYTE)HeapAlloc(heapHandle, 0, plaintextSize);
  if (NULL == plaintext) {
    HandleWin32Error(L"Read->HeapAlloc(plaintext)", GetLastError(), result);
    goto cleanup;
  }
  // Actual decryption
  status =
      BCryptDecrypt(keyHandle, ciphertext, ciphertextSize, (PVOID)&authInfo,
                    NULL, 0, plaintext, plaintextSize, &bytesWritten, 0);
  if (!BCRYPT_SUCCESS(status)) {
    HandleNTStatus(L"Read->BCryptDecrypt(2)", status, result);
    goto cleanup;
  }
  returnVal = (char*)plaintext;
cleanup:
  if (encryptionKey && INVALID_HANDLE_VALUE != heapHandle) {
    HeapFree(heapHandle, 0, encryptionKey);
  }
  if (ciphertext && INVALID_HANDLE_VALUE != heapHandle) {
    HeapFree(heapHandle, 0, ciphertext);
  }
  if (plaintext && INVALID_HANDLE_VALUE != heapHandle) {
    HeapFree(heapHandle, 0, plaintext);
  }
  if (fileBuffer && INVALID_HANDLE_VALUE != heapHandle) {
    HeapFree(heapHandle, 0, fileBuffer);
  }
  if (authInfo.pbNonce && INVALID_HANDLE_VALUE != heapHandle) {
    HeapFree(heapHandle, 0, authInfo.pbNonce);
  }
  if (authInfo.pbTag && INVALID_HANDLE_VALUE != heapHandle) {
    HeapFree(heapHandle, 0, authInfo.pbTag);
  }

  return returnVal;
}

void FlutterSecureStorageWindowsPlugin::ReadAll(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  WIN32_FIND_DATA searchRes;
  HANDLE hFile = INVALID_HANDLE_VALUE;
  std::wstring appSupportPath;

  if (!GetApplicationSupportPath(appSupportPath, result)) {
    return;
  }

  auto ret = MakePath(appSupportPath);
  if (ERROR_SUCCESS != ret) {
    HandleWin32Error(L"ReadAll->MakePath(appSupportPath)", ret, result);
    return;
  }

  hFile = FindFirstFileW((appSupportPath + L"\\*.secure").c_str(), &searchRes);
  if (INVALID_HANDLE_VALUE == hFile) {
    auto error = GetLastError();
    if (ERROR_FILE_NOT_FOUND == error) {
      // empty
      result->Success(flutter::EncodableValue(flutter::EncodableMap()));
    } else {
      HandleWin32Error(L"ReadAll->FindFirstFileW", error, result);
    }
    return;
  }

  flutter::EncodableMap creds;

  do {
    std::wstring fileName(searchRes.cFileName);
    size_t pos = fileName.find(L".secure");
    fileName.erase(pos, 7);
    std::string out = this->ConvertToUtf8(fileName);
    std::optional<std::string> val = this->Read(out, result);

    if (!val.has_value()) {
      // failure
      goto cleanup;
    }

    auto key = this->RemoveKeyPrefix(out);
    if (val.has_value()) {
      creds[key] = val.value();
      continue;
    }
  } while (0 != FindNextFileW(hFile, &searchRes));

  auto error = GetLastError();
  if (ERROR_NO_MORE_FILES != error) {
    HandleWin32Error(L"ReadAll->FindNextFile", error, result);
    goto cleanup;
  }

  // Backwards comp.
  PCREDENTIALW* pcreds;
  DWORD cred_count = 0;

  bool ok = CredEnumerateW(CREDENTIAL_FILTER.m_psz, 0, &cred_count, &pcreds);
  if (!ok) {
    error = GetLastError();
    if (ERROR_NOT_FOUND == error) {
      goto success;
    } else {
      HandleWin32Error(L"ReadAll->CredEnumerateW", error, result);
      goto cleanup;
    }
  } else {
    for (DWORD i = 0; i < cred_count; i++) {
      auto pcred = pcreds[i];
      std::string target_name = CW2A(pcred->TargetName);
      auto val = std::string((char*)pcred->CredentialBlob);
      auto key = this->RemoveKeyPrefix(target_name);
      // If the key exists then data was already read from a file, which implies
      // that the data read from the credential system is outdated
      if (creds.find(key) == creds.end()) {
        creds[key] = val;
      }
    }
  }

  CredFree(pcreds);
success:
  result->Success(flutter::EncodableValue(creds));
cleanup:
  if (INVALID_HANDLE_VALUE != hFile) {
    if (!FindClose(hFile)) {
      std::cerr << "Failed to ReadAll->FindClose, 0x" << std::hex
                << std::setw(8) << std::setfill('0') << GetLastError()
                << std::endl;
    }
  }

  return;
}

void FlutterSecureStorageWindowsPlugin::Delete(
    const std::string& key,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  std::wstring appSupportPath;
  if (!GetApplicationSupportPath(appSupportPath, result)) {
    return;
  }
  auto wstr = std::wstring(key.begin(), key.end());
  BOOL ok = DeleteFileW((appSupportPath + L"\\" + wstr + L".secure").c_str());
  if (!ok) {
    auto error = GetLastError();
    if (ERROR_FILE_NOT_FOUND != error) {
      HandleWin32Error(L"Delete->DeleteFileW", error, result);
      return;
    }
  }

  // Backwards comp.
  ok = CredDeleteW(wstr.c_str(), CRED_TYPE_GENERIC, 0);
  if (!ok) {
    auto error = GetLastError();

    // Silently ignore if we try to delete a key that doesn't exist
    if (ERROR_NOT_FOUND != error) {
      HandleWin32Error(L"Delete->CredDeleteW", error, result);
      return;
    }
  }

  result->Success();
}

void FlutterSecureStorageWindowsPlugin::DeleteAll(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  WIN32_FIND_DATA searchRes;
  HANDLE hFile;
  std::wstring appSupportPath;

  PCREDENTIALW* pcreds = NULL;

  if (!GetApplicationSupportPath(appSupportPath, result)) {
    return;
  }
  auto ret = MakePath(appSupportPath);
  if (ERROR_SUCCESS != ret) {
    HandleWin32Error(L"ReadAll->MakePath(appSupportPath)", ret, result);
    return;
  }

  hFile = FindFirstFileW((appSupportPath + L"\\*.secure").c_str(), &searchRes);
  if (INVALID_HANDLE_VALUE == hFile) {
    HandleWin32Error(L"ReadAll->FindFirstFileW", GetLastError(), result);
    return;
  }
  do {
    std::wstring fileName(searchRes.cFileName);
    BOOL ok = DeleteFileW((appSupportPath + L"\\" + fileName).c_str());
    if (!ok) {
      auto error = GetLastError();
      if (ERROR_FILE_NOT_FOUND != error) {
        HandleWin32Error(L"ReadAll->DeleteFileW", error, result);
        goto cleanup;
      }
    }
  } while (0 != FindNextFileW(hFile, &searchRes));

  {
    auto error = GetLastError();
    if (ERROR_NO_MORE_FILES != error) {
      HandleWin32Error(L"ReadAll->FindNextFile", error, result);
      goto cleanup;
    }
  }

  // Backwards comp.
  DWORD cred_count = 0;

  bool read_ok =
      CredEnumerateW(CREDENTIAL_FILTER.m_psz, 0, &cred_count, &pcreds);
  if (!read_ok) {
    auto error = GetLastError();
    if (ERROR_NOT_FOUND == error) {
      // No credentials to delete
      goto success;
    } else {
      HandleWin32Error(L"DeleteAll->CredEnumerateW", error, result);
      goto cleanup;
    }
  }

  for (DWORD i = 0; i < cred_count; i++) {
    auto pcred = pcreds[i];
    auto target_name = pcred->TargetName;

    bool delete_ok = CredDeleteW(target_name, CRED_TYPE_GENERIC, 0);
    if (!delete_ok) {
      HandleWin32Error(L"DeleteAll->CredDeleteW", GetLastError(), result);
      goto cleanup;
    }
  }

success:
  result->Success();

cleanup:
  if (INVALID_HANDLE_VALUE != hFile) {
    if (!FindClose(hFile)) {
      std::cerr << "Failed to call DeleteAll->FindClose, 0x" << std::hex
                << std::setw(8) << std::setfill('0') << GetLastError()
                << std::endl;
    }
  }

  if (pcreds) {
    CredFree(pcreds);
  }
}

void FlutterSecureStorageWindowsPlugin::ContainsKey(
    const std::string& key,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>& result) {
  std::wstring appSupportPath;
  if (!GetApplicationSupportPath(appSupportPath, result)) {
    return;
  }

  // TODO: sanitize
  std::wstring wstr = std::wstring(key.begin(), key.end());
  auto attribute =
      GetFileAttributesW((appSupportPath + L"\\" + wstr + L".secure").c_str());
  if (INVALID_FILE_ATTRIBUTES == attribute) {
    // Backwards comp.
    PCREDENTIALW pcred;
    CA2W target_name(key.c_str());

    bool ok = CredReadW(target_name.m_psz, CRED_TYPE_GENERIC, 0, &pcred);
    if (ok) {
      result->Success(flutter::EncodableValue(true));
      return;
    }

    auto error = GetLastError();
    if (ERROR_NOT_FOUND == error) {
      result->Success(flutter::EncodableValue(false));
      return;
    }

    HandleWin32Error(L"ContainsKey->GetFileAttributesW", error, result);
    return;
  }

  // TODO: directory, reparse_point handling
  result->Success(flutter::EncodableValue(true));
  return;
}
}  // namespace

void FlutterSecureStorageWindowsPluginRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  FlutterSecureStorageWindowsPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
