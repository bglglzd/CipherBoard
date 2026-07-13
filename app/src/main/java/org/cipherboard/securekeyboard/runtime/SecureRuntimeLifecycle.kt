// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime

import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.ComponentCallbacks2
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle

internal class SecureRuntimeLifecycle(
    private val application: Application,
    private val runtime: SecureKeyboardRuntime,
) : Application.ActivityLifecycleCallbacks, ComponentCallbacks2 {
    private var startedActivities = 0

    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF,
                Intent.ACTION_SHUTDOWN,
                -> runtime.lockVault()
            }
        }
    }

    fun register() {
        application.registerActivityLifecycleCallbacks(this)
        application.registerComponentCallbacks(this)
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SHUTDOWN)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            application.registerReceiver(screenReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            application.registerReceiver(screenReceiver, filter)
        }
    }

    override fun onActivityStarted(activity: Activity) {
        if (startedActivities++ == 0) runtime.onForegrounded()
    }

    override fun onActivityStopped(activity: Activity) {
        startedActivities = (startedActivities - 1).coerceAtLeast(0)
        if (startedActivities == 0 && !activity.isChangingConfigurations) runtime.onBackgrounded()
    }

    override fun onTrimMemory(level: Int) {
        if (level >= ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) runtime.onBackgrounded()
    }

    override fun onLowMemory() {
        runtime.lockIfExpired()
    }
    override fun onConfigurationChanged(newConfig: Configuration) = Unit
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
    override fun onActivityResumed(activity: Activity) = Unit
    override fun onActivityPaused(activity: Activity) = Unit
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
    override fun onActivityDestroyed(activity: Activity) = Unit
}
