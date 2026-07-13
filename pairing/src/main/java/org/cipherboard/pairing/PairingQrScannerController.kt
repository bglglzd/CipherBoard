package org.cipherboard.pairing

import android.content.Context
import android.os.SystemClock
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import java.io.Closeable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

enum class PairingQrScannerFailure {
    CAMERA_PROVIDER_UNAVAILABLE,
    CAMERA_BIND_FAILED,
    FRAME_PROCESSING_FAILED,
}

/**
 * A one-shot lifecycle-bound CameraX controller. The caller owns runtime CAMERA permission UI and
 * must construct/bind this controller only after an explicit user scan action.
 */
class PairingQrScannerController(
    context: Context,
    debounceMillis: Long = DEFAULT_DEBOUNCE_MILLIS,
) : LifecycleEventObserver, Closeable {
    private val applicationContext = context.applicationContext
    private val mainExecutor = ContextCompat.getMainExecutor(applicationContext)
    private val cameraExecutor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "cipherboard-qr-camera").apply { isDaemon = true }
    }
    private val debouncer = DuplicateDebouncer(debounceMillis)
    private val closed = AtomicBoolean(false)
    private val failureDelivered = AtomicBoolean(false)
    private val bindStarted = AtomicBoolean(false)

    @Volatile
    private var lifecycleOwner: LifecycleOwner? = null
    @Volatile
    private var cameraProvider: ProcessCameraProvider? = null
    @Volatile
    private var previewUseCase: Preview? = null
    @Volatile
    private var analysisUseCase: ImageAnalysis? = null
    @Volatile
    private var resultCallback: ((PairingQrPayload) -> Unit)? = null
    @Volatile
    private var failureCallback: ((PairingQrScannerFailure) -> Unit)? = null

    /** Must be called on the main thread after CAMERA permission has been granted. */
    fun bind(
        owner: LifecycleOwner,
        previewView: PreviewView,
        cameraSelector: CameraSelector = CameraSelector.DEFAULT_BACK_CAMERA,
        onResult: (PairingQrPayload) -> Unit,
        onFailure: (PairingQrScannerFailure) -> Unit = {},
    ) {
        check(!closed.get()) { "Scanner is closed" }
        check(bindStarted.compareAndSet(false, true)) { "Scanner can only be bound once" }
        lifecycleOwner = owner
        resultCallback = onResult
        failureCallback = onFailure
        owner.lifecycle.addObserver(this)

        val providerFuture = ProcessCameraProvider.getInstance(applicationContext)
        providerFuture.addListener(
            {
                if (closed.get()) return@addListener
                val provider = try {
                    providerFuture.get()
                } catch (_: Exception) {
                    deliverFailure(PairingQrScannerFailure.CAMERA_PROVIDER_UNAVAILABLE)
                    return@addListener
                }
                if (closed.get()) return@addListener

                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                    .also { useCase ->
                        useCase.setAnalyzer(cameraExecutor) { image ->
                            try {
                                if (!closed.get()) {
                                    val payload = PairingQrFrameDecoder.decode(image)
                                    if (payload != null && debouncer.shouldDeliver(payload, SystemClock.elapsedRealtime())) {
                                        deliverResult(payload)
                                    }
                                }
                            } catch (_: RuntimeException) {
                                deliverFailure(PairingQrScannerFailure.FRAME_PROCESSING_FAILED)
                            } finally {
                                image.close()
                            }
                        }
                    }

                try {
                    provider.bindToLifecycle(owner, cameraSelector, preview, analysis)
                    cameraProvider = provider
                    previewUseCase = preview
                    analysisUseCase = analysis
                } catch (_: RuntimeException) {
                    analysis.clearAnalyzer()
                    deliverFailure(PairingQrScannerFailure.CAMERA_BIND_FAILED)
                }
            },
            mainExecutor,
        )
    }

    override fun onStateChanged(source: LifecycleOwner, event: Lifecycle.Event) {
        if (event == Lifecycle.Event.ON_DESTROY) close()
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        resultCallback = null
        failureCallback = null
        debouncer.close()
        analysisUseCase?.clearAnalyzer()
        cameraExecutor.shutdownNow()

        val owner = lifecycleOwner
        val provider = cameraProvider
        val preview = previewUseCase
        val analysis = analysisUseCase
        lifecycleOwner = null
        cameraProvider = null
        previewUseCase = null
        analysisUseCase = null
        mainExecutor.execute {
            owner?.lifecycle?.removeObserver(this)
            if (provider != null) {
                val useCases = listOfNotNull(preview, analysis).toTypedArray()
                if (useCases.isNotEmpty()) provider.unbind(*useCases)
            }
        }
    }

    private fun deliverResult(payload: PairingQrPayload) {
        mainExecutor.execute {
            if (!closed.get()) resultCallback?.invoke(payload)
        }
    }

    private fun deliverFailure(failure: PairingQrScannerFailure) {
        if (!failureDelivered.compareAndSet(false, true)) return
        mainExecutor.execute {
            if (!closed.get()) failureCallback?.invoke(failure)
        }
    }

    companion object {
        const val DEFAULT_DEBOUNCE_MILLIS = 1_500L
    }
}
