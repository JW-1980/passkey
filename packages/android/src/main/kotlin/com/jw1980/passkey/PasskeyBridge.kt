package com.jw1980.passkey

import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException

/**
 * Why a passkey action failed. [code] is one of the error codes of the JavaScript client
 * (`cancelled`, `unsupported`, `already_registered`, `no_credentials`, `security`, `unknown`), so a
 * bridge can hand it over unchanged: reject the call with an object `{ code, message }`.
 */
public class PasskeyBridgeException(
    public val code: String,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Passkeys for a webview-based Android app (for example Tauri or Capacitor), through Android's
 * Credential Manager.
 *
 * The webview cannot use the site's passkeys itself. The page asks the server for WebAuthn options
 * as usual, passes their JSON over the app's bridge to [create] or [get], and posts the JSON that
 * comes back to the server. In the page, wrap the bridge with `bridgeAuthenticator` of the
 * JavaScript client.
 *
 * The app must be associated with the relying party's domain: the server publishes
 * `/.well-known/assetlinks.json` for the app's package and signing certificate, and lists the
 * app's `android:apk-key-hash:…` origin as allowed.
 */
public class PasskeyBridge(
    private val credentialManager: (Context) -> CredentialManager = { CredentialManager.create(it) },
) {
    /**
     * Creates a passkey.
     *
     * @param activityContext An **Activity** context: the system sheet is shown on top of it.
     * @param requestJson The `publicKey` creation options from the server, as JSON text.
     * @return The registration response as JSON text, ready to post to the server.
     * @throws PasskeyBridgeException
     */
    public suspend fun create(activityContext: Context, requestJson: String): String {
        try {
            val response = credentialManager(activityContext).createCredential(
                activityContext,
                CreatePublicKeyCredentialRequest(requestJson),
            )
            if (response !is CreatePublicKeyCredentialResponse) {
                throw PasskeyBridgeException("unknown", "The device did not return a passkey.")
            }
            return response.registrationResponseJson
        } catch (failure: CreateCredentialException) {
            throw PasskeyErrors.fromCreate(failure)
        }
    }

    /**
     * Signs in with a passkey.
     *
     * @param activityContext An **Activity** context: the system sheet is shown on top of it.
     * @param requestJson The `publicKey` request options from the server, as JSON text.
     * @return The authentication response as JSON text, ready to post to the server.
     * @throws PasskeyBridgeException
     */
    public suspend fun get(activityContext: Context, requestJson: String): String {
        try {
            val response = credentialManager(activityContext).getCredential(
                activityContext,
                GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson))),
            )
            val credential = response.credential as? PublicKeyCredential
                ?: throw PasskeyBridgeException("unknown", "The device did not return a passkey.")
            return credential.authenticationResponseJson
        } catch (failure: GetCredentialException) {
            throw PasskeyErrors.fromGet(failure)
        }
    }
}

/** Maps Credential Manager's failures to the error codes of the JavaScript client. */
public object PasskeyErrors {
    public fun fromCreate(failure: CreateCredentialException): PasskeyBridgeException {
        val code = when (failure) {
            is CreateCredentialCancellationException, is CreateCredentialInterruptedException -> "cancelled"
            is CreateCredentialUnsupportedException, is CreateCredentialProviderConfigurationException -> "unsupported"
            is CreatePublicKeyCredentialDomException -> fromDomError(failure.domError.type)
            else -> "unknown"
        }
        return PasskeyBridgeException(code, messageFor(code), failure)
    }

    public fun fromGet(failure: GetCredentialException): PasskeyBridgeException {
        val code = when (failure) {
            is GetCredentialCancellationException, is GetCredentialInterruptedException -> "cancelled"
            is NoCredentialException -> "no_credentials"
            is GetCredentialUnsupportedException, is GetCredentialProviderConfigurationException -> "unsupported"
            is GetPublicKeyCredentialDomException -> fromDomError(failure.domError.type)
            else -> "unknown"
        }
        return PasskeyBridgeException(code, messageFor(code), failure)
    }

    /**
     * Credential Manager reports WebAuthn's DOM errors by type, for example
     * `androidx.credentials.TYPE_INVALID_STATE_ERROR`.
     */
    internal fun fromDomError(type: String): String = when {
        type.endsWith("TYPE_INVALID_STATE_ERROR") -> "already_registered"
        type.endsWith("TYPE_NOT_ALLOWED_ERROR") || type.endsWith("TYPE_ABORT_ERROR") ||
            type.endsWith("TYPE_TIMEOUT_ERROR") -> "cancelled"
        type.endsWith("TYPE_SECURITY_ERROR") -> "security"
        type.endsWith("TYPE_NOT_SUPPORTED_ERROR") -> "unsupported"
        else -> "unknown"
    }

    private fun messageFor(code: String): String = when (code) {
        "cancelled" -> "The passkey prompt was closed."
        "unsupported" -> "Passkeys are not available on this device."
        "already_registered" -> "This device already has a passkey for this account."
        "no_credentials" -> "No passkey for this app is available on this device."
        "security" -> "This app may not use the passkeys of this site."
        else -> "The passkey prompt failed."
    }
}
