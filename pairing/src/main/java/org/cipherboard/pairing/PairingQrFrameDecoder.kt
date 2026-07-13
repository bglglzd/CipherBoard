package org.cipherboard.pairing

import androidx.camera.core.ImageProxy
import com.google.zxing.PlanarYUVLuminanceSource

internal object PairingQrFrameDecoder {
    private const val MAX_FRAME_WIDTH = 2560
    private const val MAX_FRAME_HEIGHT = 2560
    private const val MAX_FRAME_PIXELS = 4 * 1024 * 1024
    private const val MAX_Y_PLANE_BYTES = 8 * 1024 * 1024

    fun decode(image: ImageProxy): PairingQrPayload? {
        val width = image.width
        val height = image.height
        if (width !in 1..MAX_FRAME_WIDTH || height !in 1..MAX_FRAME_HEIGHT ||
            width.toLong() * height.toLong() > MAX_FRAME_PIXELS
        ) {
            return null
        }
        val plane = image.planes.firstOrNull() ?: return null
        val pixelStride = plane.pixelStride
        val rowStride = plane.rowStride
        if (pixelStride <= 0 || rowStride <= 0) return null

        val buffer = plane.buffer.duplicate()
        buffer.rewind()
        if (buffer.remaining() <= 0 || buffer.remaining() > MAX_Y_PLANE_BYTES) return null
        val yPlane = ByteArray(buffer.remaining())
        val packed = ByteArray(width * height)
        return try {
            buffer.get(yPlane)
            if (!packLuma(yPlane, packed, width, height, rowStride, pixelStride)) return null
            val source = PlanarYUVLuminanceSource(
                packed,
                width,
                height,
                0,
                0,
                width,
                height,
                false,
            )
            PairingQrCodec.decodeLuminance(source)
        } finally {
            yPlane.fill(0)
            packed.fill(0)
        }
    }

    private fun packLuma(
        source: ByteArray,
        destination: ByteArray,
        width: Int,
        height: Int,
        rowStride: Int,
        pixelStride: Int,
    ): Boolean {
        val lastIndex = (height - 1L) * rowStride + (width - 1L) * pixelStride
        if (lastIndex !in 0 until source.size.toLong()) return false
        for (y in 0 until height) {
            val sourceRow = y * rowStride
            val destinationRow = y * width
            for (x in 0 until width) {
                destination[destinationRow + x] = source[sourceRow + x * pixelStride]
            }
        }
        return true
    }
}
