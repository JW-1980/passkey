package com.jw1980.passkey

import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.domerrors.SecurityError
import androidx.credentials.exceptions.domerrors.TimeoutError
import androidx.credentials.exceptions.domerrors.DataError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

class PasskeyErrorsTest {
    @Test
    fun `creation failures map to the client's codes`() {
        val cases = listOf(
            CreateCredentialCancellationException() to "cancelled",
            CreateCredentialInterruptedException() to "cancelled",
            CreateCredentialUnsupportedException() to "unsupported",
            CreateCredentialProviderConfigurationException() to "unsupported",
            CreateCredentialUnknownException() to "unknown",
            CreatePublicKeyCredentialDomException(InvalidStateError()) to "already_registered",
            CreatePublicKeyCredentialDomException(NotAllowedError()) to "cancelled",
            CreatePublicKeyCredentialDomException(TimeoutError()) to "cancelled",
            CreatePublicKeyCredentialDomException(SecurityError()) to "security",
            CreatePublicKeyCredentialDomException(NotSupportedError()) to "unsupported",
            CreatePublicKeyCredentialDomException(DataError()) to "unknown",
        )
        for ((failure, code) in cases) {
            val mapped = PasskeyErrors.fromCreate(failure)
            assertEquals(code, mapped.code, failure.toString())
            assertSame(failure, mapped.cause)
        }
    }

    @Test
    fun `sign-in failures map to the client's codes`() {
        val cases = listOf(
            GetCredentialCancellationException() to "cancelled",
            GetCredentialInterruptedException() to "cancelled",
            NoCredentialException() to "no_credentials",
            GetCredentialUnsupportedException() to "unsupported",
            GetCredentialProviderConfigurationException() to "unsupported",
            GetCredentialUnknownException() to "unknown",
            GetPublicKeyCredentialDomException(NotAllowedError()) to "cancelled",
            GetPublicKeyCredentialDomException(SecurityError()) to "security",
            GetPublicKeyCredentialDomException(DataError()) to "unknown",
        )
        for ((failure, code) in cases) {
            val mapped = PasskeyErrors.fromGet(failure)
            assertEquals(code, mapped.code, failure.toString())
            assertSame(failure, mapped.cause)
        }
    }

    @Test
    fun `the message never repeats the platform's internal text`() {
        val mapped = PasskeyErrors.fromGet(GetCredentialUnknownException("internal: provider crashed at 0x1f"))
        assertEquals("The passkey prompt failed.", mapped.message)
    }
}
