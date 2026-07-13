package org.cipherboard.cryptocore

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CborWireTest {
    @Test
    fun deterministicRoundTrip() {
        val encoded = CborWriter().use { writer ->
            writer.array(5)
                .uint(1)
                .uint(23)
                .uint(65_536)
                .bytes(byteArrayOf(0, 1, 2, 0xff.toByte()))
                .array(0)
                .finish()
        }
        val reader = CborReader(encoded)
        reader.array(5)
        assertEquals(1, reader.uint())
        assertEquals(23, reader.uint())
        assertEquals(65_536, reader.uint())
        assertContentEquals(byteArrayOf(0, 1, 2, 0xff.toByte()), reader.bytes(4))
        reader.array(0)
        reader.finish()
        encoded.fill(0)
    }

    @Test
    fun rejectsNonCanonicalInteger() {
        val nonCanonicalOne = byteArrayOf(0x18, 0x01)
        assertFailsWith<IllegalArgumentException> { CborReader(nonCanonicalOne).uint() }
    }

    @Test
    fun rejectsIndefiniteAndTrailingData() {
        assertFailsWith<IllegalArgumentException> { CborReader(byteArrayOf(0x9f.toByte())).arrayLength() }

        val trailing = CborWriter().use { it.array(0).finish() } + byteArrayOf(0)
        val reader = CborReader(trailing)
        reader.array(0)
        assertFailsWith<IllegalArgumentException> { reader.finish() }
        trailing.fill(0)
    }

    @Test
    fun enforcesByteStringLimit() {
        val encoded = CborWriter().use { it.bytes(ByteArray(17)).finish() }
        assertFailsWith<IllegalArgumentException> { CborReader(encoded).bytes(16) }
        encoded.fill(0)
    }

    @Test
    fun ownedSecretTakesOwnershipAndClears() {
        val source = byteArrayOf(1, 2, 3, 4)
        val secret = OwnedSecret.takeOwnership(source)
        secret.use { assertContentEquals(byteArrayOf(1, 2, 3, 4), it) }
        secret.clear()
        assertTrue(source.all { it == 0.toByte() })
        assertTrue(secret.isCleared)
        assertFailsWith<IllegalStateException> { secret.use { Unit } }
        assertEquals("OwnedSecret(size=0, cleared=true)", secret.toString())
    }

    @Test
    fun asciiRejectsUnicodeTransportText() {
        assertFailsWith<IllegalArgumentException> {
            CborWriter().use { it.ascii("CB1:кириллица").finish() }
        }
    }
}
