// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.secure

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OwnedMainThreadResultHandoffsTest {
    @Test
    fun `drain closes a queued worker result before its callback is removed`() {
        val callbacks = CopyOnWriteArrayList<Runnable>()
        val delivered = AtomicInteger()
        val closed = AtomicInteger()
        val handoffs = OwnedMainThreadResultHandoffs(
            postToMain = { callback -> callbacks.add(callback) },
            removeFromMain = callbacks::remove,
        )
        handoffs.open()
        val token = handoffs.capture()

        val worker = thread {
            handoffs.post(
                token = token,
                value = OwnedTestResult(closed),
                deliver = { delivered.incrementAndGet() },
                abandon = OwnedTestResult::close,
            )
        }
        worker.join()
        assertEquals(1, callbacks.size)

        handoffs.drain()

        assertEquals(1, closed.get())
        assertEquals(0, delivered.get())
        assertTrue(callbacks.isEmpty())
    }

    @Test
    fun `close rejects and closes a result from a late worker callback`() {
        val callbacks = CopyOnWriteArrayList<Runnable>()
        val delivered = AtomicInteger()
        val closed = AtomicInteger()
        val handoffs = OwnedMainThreadResultHandoffs(
            postToMain = { callback -> callbacks.add(callback) },
            removeFromMain = callbacks::remove,
        )
        handoffs.open()
        val token = handoffs.capture()
        handoffs.close()

        handoffs.post(
            token = token,
            value = OwnedTestResult(closed),
            deliver = { delivered.incrementAndGet() },
            abandon = OwnedTestResult::close,
        )

        assertEquals(1, closed.get())
        assertEquals(0, delivered.get())
        assertTrue(callbacks.isEmpty())
    }

    @Test
    fun `drain invalidates and closes a result completed after cancellation`() {
        val callbacks = CopyOnWriteArrayList<Runnable>()
        val delivered = AtomicInteger()
        val closed = AtomicInteger()
        val handoffs = OwnedMainThreadResultHandoffs(
            postToMain = { callback -> callbacks.add(callback) },
            removeFromMain = callbacks::remove,
        )
        handoffs.open()
        val cancelledToken = handoffs.capture()

        handoffs.drain()
        handoffs.post(
            token = cancelledToken,
            value = OwnedTestResult(closed),
            deliver = { delivered.incrementAndGet() },
            abandon = OwnedTestResult::close,
        )

        assertEquals(1, closed.get())
        assertEquals(0, delivered.get())
        assertTrue(callbacks.isEmpty())
    }

    @Test
    fun `close owns the result even when posting races lifecycle teardown`() {
        val postingStarted = CountDownLatch(1)
        val finishPosting = CountDownLatch(1)
        val callbackAfterClose = CopyOnWriteArrayList<Runnable>()
        val delivered = AtomicInteger()
        val closed = AtomicInteger()
        val handoffs = OwnedMainThreadResultHandoffs(
            postToMain = { callback ->
                postingStarted.countDown()
                assertTrue(finishPosting.await(5, TimeUnit.SECONDS))
                callbackAfterClose.add(callback)
            },
            removeFromMain = callbackAfterClose::remove,
        )
        handoffs.open()
        val token = handoffs.capture()

        val worker = thread {
            handoffs.post(
                token = token,
                value = OwnedTestResult(closed),
                deliver = { delivered.incrementAndGet() },
                abandon = OwnedTestResult::close,
            )
        }
        assertTrue(postingStarted.await(5, TimeUnit.SECONDS))

        handoffs.close()
        finishPosting.countDown()
        worker.join()

        assertEquals(1, closed.get())
        assertEquals(0, delivered.get())
        assertEquals(1, callbackAfterClose.size)
        callbackAfterClose.single().run()
        assertEquals(0, delivered.get())
        assertEquals(1, closed.get())
    }

    @Test
    fun `claimed result is delivered exactly once and no longer drained`() {
        var callback: Runnable? = null
        val delivered = AtomicInteger()
        val closed = AtomicInteger()
        val handoffs = OwnedMainThreadResultHandoffs(
            postToMain = { queued ->
                callback = queued
                true
            },
            removeFromMain = { removed ->
                if (callback === removed) callback = null
            },
        )
        handoffs.open()
        val token = handoffs.capture()
        handoffs.post(
            token = token,
            value = OwnedTestResult(closed),
            deliver = { delivered.incrementAndGet() },
            abandon = OwnedTestResult::close,
        )

        requireNotNull(callback).run()
        requireNotNull(callback).run()
        handoffs.close()

        assertEquals(1, delivered.get())
        assertEquals(0, closed.get())
    }

    private class OwnedTestResult(
        private val closeCount: AtomicInteger,
    ) {
        fun close() {
            closeCount.incrementAndGet()
        }
    }
}
