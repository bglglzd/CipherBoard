// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import android.os.IBinder
import org.cipherboard.securekeyboard.runtime.PreparedOutbound
import org.cipherboard.securestorage.PendingOutboundState
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.mock

class SecureImeBridgeTest {
    private val hostConnectionToken: IBinder = mock(IBinder::class.java)

    @Before
    fun setUp() = SecureImeBridge.clear()

    @After
    fun tearDown() = SecureImeBridge.clear()

    @Test
    fun `delivery is scoped to original host and completes after exact commit`() {
        val operationId = ByteArray(16) { (it + 1).toByte() }
        val events = mutableListOf<String>()
        val outbound = outbound(operationId, listOf("CB1:first", "CB1:second")) {
            events += "mark"
            true
        }
        val token = requireNotNull(begin())
        assertTrue(SecureImeBridge.activateComposer(token))
        assertTrue(SecureImeBridge.arm(token, outbound))

        var wrongScopeCalled = false
        assertEquals(
            CiphertextDeliveryResult.NO_HANDOFF,
            deliver(fieldId = HOST_FIELD + 1, committer = {
                wrongScopeCalled = true
                true
            }, completion = { true }),
        )
        assertFalse(wrongScopeCalled)
        var committed: String? = null
        var completedId: ByteArray? = null
        val result = deliver(
            connectionToken = mock(IBinder::class.java),
            committer = { ciphertext ->
                events += "commit"
                committed = ciphertext
                true
            },
            completion = { id ->
                events += "complete"
                completedId = id.copyOf()
                true
            },
        )

        assertEquals(CiphertextDeliveryResult.COMMITTED_AND_COMPLETED, result)
        assertEquals("CB1:first\nCB1:second", committed)
        assertArrayEquals(operationId, completedId)
        assertEquals(listOf("mark", "commit", "complete"), events)
        assertFalse(SecureImeBridge.hasSessionForTest())
        completedId?.fill(0)
        operationId.fill(0)
    }

    @Test
    fun `rotated system connection token is accepted but changed field is not`() {
        val operationId = ByteArray(16) { 0x31 }
        val token = requireNotNull(begin())
        assertTrue(SecureImeBridge.activateComposer(token))
        assertTrue(
            SecureImeBridge.arm(
                token,
                outbound(operationId, listOf("CB1:rotated-binder")),
            ),
        )
        var attempts = 0
        assertEquals(
            CiphertextDeliveryResult.NO_HANDOFF,
            deliver(fieldId = HOST_FIELD + 1, connectionToken = mock(IBinder::class.java), committer = {
                attempts += 1
                true
            }, completion = { true }),
        )
        assertEquals(0, attempts)
        assertEquals(
            CiphertextDeliveryResult.COMMITTED_AND_COMPLETED,
            deliver(connectionToken = mock(IBinder::class.java), committer = {
                attempts += 1
                it == "CB1:rotated-binder"
            }, completion = { true }),
        )
        assertEquals(1, attempts)
        operationId.fill(0)
    }

    @Test
    fun `each host commit attempt is one shot and durable pending remains explicit`() {
        val operationId = ByteArray(16) { 7 }
        val token = requireNotNull(begin())
        val events = mutableListOf<String>()
        assertTrue(SecureImeBridge.activateComposer(token))
        assertTrue(
            SecureImeBridge.arm(
                token,
                outbound(operationId, listOf("CB1:pending")) {
                    events += "mark"
                    true
                },
            ),
        )

        var completionCalls = 0
        assertEquals(
            CiphertextDeliveryResult.HOST_COMMIT_UNCERTAIN,
            deliver(committer = {
                events += "commit"
                false
            }, completion = {
                completionCalls++
                true
            }),
        )
        assertEquals(listOf("mark", "commit"), events)
        assertEquals(0, completionCalls)
        assertFalse(SecureImeBridge.hasSessionForTest())

        assertEquals(
            CiphertextDeliveryResult.NO_HANDOFF,
            deliver(committer = { it == "CB1:pending" }, completion = {
                completionCalls++
                false
            }),
        )
        assertEquals(0, completionCalls)
        assertFalse(SecureImeBridge.hasSessionForTest())

        var duplicateCommit = false
        assertEquals(
            CiphertextDeliveryResult.NO_HANDOFF,
            deliver(committer = {
                duplicateCommit = true
                true
            }, completion = { true }),
        )
        assertFalse(duplicateCommit)
        operationId.fill(0)
    }

    @Test
    fun `composer token gates arming and cancellation`() {
        val operationId = ByteArray(16) { 3 }
        val outbound = outbound(operationId, listOf("CB1:exact"))
        val token = requireNotNull(begin())

        assertFalse(SecureImeBridge.arm(token, outbound))
        assertFalse(SecureImeBridge.activateComposer("wrong-token"))
        assertTrue(SecureImeBridge.activateComposer(token))
        assertFalse(SecureImeBridge.arm("wrong-token", outbound))
        assertTrue(SecureImeBridge.arm(token, outbound))
        assertFalse(SecureImeBridge.arm(token, outbound))

        SecureImeBridge.cancelSession("wrong-token")
        assertTrue(SecureImeBridge.hasSessionForTest())
        SecureImeBridge.cancelSession(token)
        assertFalse(SecureImeBridge.hasSessionForTest())
        operationId.fill(0)
    }

    @Test
    fun `configuration recreation can reactivate the same composer token`() {
        val operationId = ByteArray(16) { 9 }
        val token = requireNotNull(begin())

        assertTrue(SecureImeBridge.activateComposer(token))
        // A recreated Activity reads the unchanged opaque token from its Intent.
        assertTrue(SecureImeBridge.activateComposer(token))
        assertTrue(
            SecureImeBridge.arm(
                token,
                outbound(operationId, listOf("CB1:rotated")),
            ),
        )
        assertEquals(
            CiphertextDeliveryResult.COMMITTED_AND_COMPLETED,
            deliver(committer = { it == "CB1:rotated" }, completion = { true }),
        )
        operationId.fill(0)
    }

    @Test
    fun `own application editor cannot become a delivery host`() {
        assertNull(
            SecureImeBridge.beginSession(
                packageName = HOST_PACKAGE,
                uid = HOST_UID,
                connectionToken = hostConnectionToken,
                fieldId = HOST_FIELD,
                fieldName = HOST_FIELD_NAME,
                inputType = HOST_INPUT_TYPE,
                imeOptions = HOST_IME_OPTIONS,
                privateImeOptions = HOST_PRIVATE_IME_OPTIONS,
                initialSelectionStart = HOST_SELECTION_START,
                initialSelectionEnd = HOST_SELECTION_END,
                ownPackageName = HOST_PACKAGE,
            ),
        )
    }

    @Test
    fun `failed durable boundary prevents host commit and consumes handoff`() {
        val operationId = ByteArray(16) { 0x44 }
        val token = requireNotNull(begin())
        assertTrue(SecureImeBridge.activateComposer(token))
        assertTrue(SecureImeBridge.arm(token, outbound(operationId, listOf("CB1:blocked")) { false }))

        var commitCalled = false
        assertEquals(
            CiphertextDeliveryResult.NO_HANDOFF,
            deliver(committer = {
                commitCalled = true
                true
            }, completion = { true }),
        )

        assertFalse(commitCalled)
        assertFalse(SecureImeBridge.hasSessionForTest())
        operationId.fill(0)
    }

    @Test
    fun `uncertain outbound cannot arm automatic retry`() {
        val operationId = ByteArray(16) { 0x45 }
        val token = requireNotNull(begin())
        assertTrue(SecureImeBridge.activateComposer(token))
        assertFalse(
            SecureImeBridge.arm(
                token,
                outbound(
                    operationId,
                    listOf("CB1:uncertain"),
                    PendingOutboundState.COMMIT_UNCERTAIN,
                ),
            ),
        )
        operationId.fill(0)
    }

    private fun outbound(
        operationId: ByteArray,
        parts: List<String>,
        state: PendingOutboundState = PendingOutboundState.READY,
        marker: (ByteArray) -> Boolean = { true },
    ): PreparedOutbound = PreparedOutbound(
        ByteArray(16) { 3 },
        operationId,
        parts,
        state,
        marker,
    )

    private fun begin(): String? = SecureImeBridge.beginSession(
        packageName = HOST_PACKAGE,
        uid = HOST_UID,
        connectionToken = hostConnectionToken,
        fieldId = HOST_FIELD,
        fieldName = HOST_FIELD_NAME,
        inputType = HOST_INPUT_TYPE,
        imeOptions = HOST_IME_OPTIONS,
        privateImeOptions = HOST_PRIVATE_IME_OPTIONS,
        initialSelectionStart = HOST_SELECTION_START,
        initialSelectionEnd = HOST_SELECTION_END,
        ownPackageName = OWN_PACKAGE,
    )

    private fun deliver(
        fieldId: Int = HOST_FIELD,
        connectionToken: IBinder = hostConnectionToken,
        committer: (String) -> Boolean,
        completion: (ByteArray) -> Boolean,
    ): CiphertextDeliveryResult = SecureImeBridge.deliver(
        packageName = HOST_PACKAGE,
        uid = HOST_UID,
        connectionToken = connectionToken,
        fieldId = fieldId,
        fieldName = HOST_FIELD_NAME,
        inputType = HOST_INPUT_TYPE,
        imeOptions = HOST_IME_OPTIONS,
        privateImeOptions = HOST_PRIVATE_IME_OPTIONS,
        initialSelectionStart = HOST_SELECTION_START,
        initialSelectionEnd = HOST_SELECTION_END,
        committer = CiphertextCommitter(committer),
        completion = OutboundCompletion(completion),
    )

    private companion object {
        const val HOST_PACKAGE = "example.transport"
        const val OWN_PACKAGE = "org.cipherboard.securekeyboard"
        const val HOST_UID = 10_123
        const val HOST_FIELD = 42
        const val HOST_FIELD_NAME = "message"
        const val HOST_INPUT_TYPE = 0x20001
        const val HOST_IME_OPTIONS = 0x40000006
        const val HOST_PRIVATE_IME_OPTIONS = "transport.compose"
        const val HOST_SELECTION_START = 4
        const val HOST_SELECTION_END = 4
    }
}
