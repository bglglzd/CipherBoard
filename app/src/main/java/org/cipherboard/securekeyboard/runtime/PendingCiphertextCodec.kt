// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

/** Strict length-prefixed encoding used only inside an encrypted pending-outbound record. */
internal object PendingCiphertextCodec {
    private const val VERSION = 1
    private const val MAX_PARTS = 128
    private const val MAX_PART_BYTES = 32 * 1024
    private const val MAX_ENCODED_BYTES = 5 * 1024 * 1024

    fun encode(parts: List<String>): ByteArray {
        require(parts.size in 1..MAX_PARTS)
        val encodedParts = ArrayList<ByteArray>(parts.size)
        try {
            parts.forEach { part ->
                require(part.all { it.code in 0..0x7f })
                val encoded = part.toByteArray(StandardCharsets.US_ASCII)
                require(encoded.size in 1..MAX_PART_BYTES)
                encodedParts += encoded
            }
            val output = ByteArrayOutputStream()
            DataOutputStream(output).use { writer ->
                writer.writeInt(MAGIC)
                writer.writeByte(VERSION)
                writer.writeShort(encodedParts.size)
                encodedParts.forEach { encoded ->
                    writer.writeInt(encoded.size)
                    writer.write(encoded)
                }
            }
            return output.toByteArray().also { require(it.size <= MAX_ENCODED_BYTES) }
        } finally {
            encodedParts.forEach { it.fill(0) }
        }
    }

    fun decode(encoded: ByteArray): List<String> {
        require(encoded.size in HEADER_BYTES..MAX_ENCODED_BYTES)
        return DataInputStream(ByteArrayInputStream(encoded)).use { reader ->
            require(reader.readInt() == MAGIC)
            require(reader.readUnsignedByte() == VERSION)
            val count = reader.readUnsignedShort()
            require(count in 1..MAX_PARTS)
            val parts = ArrayList<String>(count)
            repeat(count) {
                val length = reader.readInt()
                require(length in 1..MAX_PART_BYTES && length <= reader.available())
                val bytes = ByteArray(length)
                try {
                    reader.readFully(bytes)
                    require(bytes.all { it.toInt() in 0..0x7f })
                    parts += String(bytes, StandardCharsets.US_ASCII)
                } finally {
                    bytes.fill(0)
                }
            }
            require(reader.available() == 0)
            parts
        }
    }

    private const val MAGIC = 0x4342504f // CBPO
    private const val HEADER_BYTES = 7
}
