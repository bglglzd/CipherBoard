package org.cipherboard.pairing

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class PairingQrCodecTest {
    @Test
    fun offerAndResponseRoundTripThroughBitmap() {
        listOf(
            "CBO1:eyJrZXkiOiJhYmMifQ",
            "CBR1:response-id:0123456789_-",
        ).forEach { raw ->
            val bitmap = PairingQrCodec.encodeBitmap(raw, 512)
            assertEquals(PairingQrPayload.parse(raw), PairingQrCodec.decodeBitmap(bitmap))
            bitmap.recycle()
        }
    }

    @Test
    fun generationBoundsBitmapMemory() {
        val payload = PairingQrPayload.parse("CBO1:abc")
        assertEncodeReason(PairingQrEncodeError.INVALID_SIZE) {
            PairingQrCodec.encodeBitmap(payload, 127)
        }
        assertEncodeReason(PairingQrEncodeError.INVALID_SIZE) {
            PairingQrCodec.encodeBitmap(payload, 2049)
        }
    }

    @Test
    fun physicallyOversizedSingleQrIsRejectedWithoutTruncation() {
        val raw = PairingQrPayload.OFFER_PREFIX + "a".repeat(8_000)
        assertEncodeReason(PairingQrEncodeError.PAYLOAD_DOES_NOT_FIT) {
            PairingQrCodec.encodeBitmap(raw, 512)
        }
    }

    @Test
    fun decoderIgnoresQrWithUnsupportedProtocolAndBlankImages() {
        val matrix = QRCodeWriter().encode("https://example.invalid", BarcodeFormat.QR_CODE, 256, 256)
        val pixels = IntArray(256 * 256) { index ->
            val x = index % 256
            val y = index / 256
            if (matrix[x, y]) -0x1000000 else -0x1
        }
        val unrelated = Bitmap.createBitmap(pixels, 256, 256, Bitmap.Config.ARGB_8888)
        assertNull(PairingQrCodec.decodeBitmap(unrelated))
        unrelated.recycle()

        val blank = Bitmap.createBitmap(256, 256, Bitmap.Config.ARGB_8888)
        blank.eraseColor(-0x1)
        assertNull(PairingQrCodec.decodeBitmap(blank))
        blank.recycle()
    }

    private fun assertEncodeReason(expected: PairingQrEncodeError, block: () -> Unit) {
        val error = assertThrows(PairingQrEncodeException::class.java, block)
        assertEquals(expected, error.reason)
    }
}
