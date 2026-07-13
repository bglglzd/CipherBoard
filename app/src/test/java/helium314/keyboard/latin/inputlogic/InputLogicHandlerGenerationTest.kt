// SPDX-License-Identifier: GPL-3.0-only
package helium314.keyboard.latin.inputlogic

import helium314.keyboard.latin.LatinIME
import org.junit.After
import org.junit.Before
import org.junit.runner.RunWith
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE)
class InputLogicHandlerGenerationTest {
    private lateinit var uiHandler: LatinIME.UIHandler
    private lateinit var handler: InputLogicHandler

    @Before
    fun setUp() {
        uiHandler = mock(LatinIME.UIHandler::class.java)
        handler = InputLogicHandler(uiHandler, mock(InputLogic::class.java))
    }

    @After
    fun tearDown() {
        handler.mNonUIThreadHandler.looper.quitSafely()
    }

    @Test
    fun `reset invalidates previous generation and clears batch state`() {
        assertTrue(handler.isGenerationCurrent(0))
        handler.onStartBatchInput()
        assertTrue(handler.isInBatchInput)

        handler.reset()

        assertFalse(handler.isInBatchInput)
        assertFalse(handler.isGenerationCurrent(0))
        assertTrue(handler.isGenerationCurrent(1))
        verify(uiHandler).cancelGestureMessages()
    }

    @Test
    fun `cancel invalidates previous generation and clears batch state`() {
        assertTrue(handler.isGenerationCurrent(0))
        handler.onStartBatchInput()
        assertTrue(handler.isInBatchInput)

        handler.onCancelBatchInput()

        assertFalse(handler.isInBatchInput)
        assertFalse(handler.isGenerationCurrent(0))
        assertTrue(handler.isGenerationCurrent(1))
        verify(uiHandler).cancelGestureMessages()
    }
}
