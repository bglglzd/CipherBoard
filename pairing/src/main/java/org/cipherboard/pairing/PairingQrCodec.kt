package org.cipherboard.pairing

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.ChecksumException
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.FormatException
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.WriterException
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.nio.charset.StandardCharsets
import java.util.EnumMap

enum class PairingQrEncodeError {
    INVALID_SIZE,
    PAYLOAD_DOES_NOT_FIT,
}

class PairingQrEncodeException(
    val reason: PairingQrEncodeError,
    cause: Throwable? = null,
) : IllegalArgumentException("Cannot encode pairing QR: ${reason.name}", cause)

object PairingQrCodec {
    private const val MIN_BITMAP_SIZE = 128
    private const val MAX_BITMAP_SIZE = 2048
    private const val MAX_BITMAP_PIXELS = MAX_BITMAP_SIZE * MAX_BITMAP_SIZE

    @JvmStatic
    fun encodeBitmap(rawPayload: String, sizePx: Int): Bitmap =
        encodeBitmap(PairingQrPayload.parse(rawPayload), sizePx)

    @JvmStatic
    fun encodeBitmap(payload: PairingQrPayload, sizePx: Int): Bitmap {
        if (sizePx !in MIN_BITMAP_SIZE..MAX_BITMAP_SIZE) {
            throw PairingQrEncodeException(PairingQrEncodeError.INVALID_SIZE)
        }
        val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
            put(EncodeHintType.CHARACTER_SET, StandardCharsets.US_ASCII.name())
            put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M)
            put(EncodeHintType.MARGIN, 2)
        }
        val matrix = try {
            QRCodeWriter().encode(payload.value, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        } catch (e: WriterException) {
            throw PairingQrEncodeException(PairingQrEncodeError.PAYLOAD_DOES_NOT_FIT, e)
        }
        return matrix.toBitmap()
    }

    @JvmStatic
    fun decodeBitmap(bitmap: Bitmap): PairingQrPayload? {
        val width = bitmap.width
        val height = bitmap.height
        if (width <= 0 || height <= 0 || width > MAX_BITMAP_SIZE || height > MAX_BITMAP_SIZE ||
            width.toLong() * height.toLong() > MAX_BITMAP_PIXELS.toLong()
        ) {
            return null
        }
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
        return decodeLuminance(RGBLuminanceSource(width, height, pixels))
    }

    internal fun decodeLuminance(source: com.google.zxing.LuminanceSource): PairingQrPayload? {
        val reader = MultiFormatReader()
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
            put(DecodeHintType.CHARACTER_SET, StandardCharsets.US_ASCII.name())
        }
        return try {
            val result = reader.decode(BinaryBitmap(HybridBinarizer(source)), hints)
            if (result.barcodeFormat != BarcodeFormat.QR_CODE) null else PairingQrPayload.parseOrNull(result.text)
        } catch (_: NotFoundException) {
            null
        } catch (_: ChecksumException) {
            null
        } catch (_: FormatException) {
            null
        } finally {
            reader.reset()
        }
    }

    private fun BitMatrix.toBitmap(): Bitmap {
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val rowOffset = y * width
            for (x in 0 until width) {
                pixels[rowOffset + x] = if (get(x, y)) BLACK else WHITE
            }
        }
        return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888)
    }

    private const val BLACK = -0x1000000
    private const val WHITE = -0x1
}
