/*
 * Copyright (C) 2012 The Android Open Source Project
 * modified
 * SPDX-License-Identifier: Apache-2.0 AND GPL-3.0-only
 */

package helium314.keyboard.latin.utils;

import android.annotation.SuppressLint;
import android.app.Application;

import helium314.keyboard.latin.App;
import helium314.keyboard.latin.BuildConfig;

import java.io.File;

@SuppressLint("PrivateApi") // Reflection is a fallback when App has not published its context yet.
public final class JniUtils {
    private static final String TAG = JniUtils.class.getSimpleName();
    public static final String JNI_LIB_NAME = "jni_latinime";
    private static final String JNI_LIB_NAME_GOOGLE = "jni_latinimegoogle";

    public static boolean sHaveGestureLib = false;
    static {
        Application app = App.Companion.getApp();
        if (app == null) {
            try {
                app = (Application) Class.forName("android.app.ActivityThread")
                        .getMethod("currentApplication").invoke(null, (Object[]) null);
            } catch (Exception ignored) {
                // The packaged non-gesture library remains available without an application.
            }
        }

        // A gesture library executes in the same process as the IME and secure composer. Never
        // load a user-selected path merely because it exists: the installer and this startup path
        // both require a pinned SHA-256 for the device ABI.
        if (!BuildConfig.BUILD_TYPE.equals("nouserlib") && app != null) {
            final File importedLibrary = GestureLibraryInstaller.INSTANCE
                    .validInstalledLibrary(
                            app.getFilesDir(), GestureLibraryInstaller.INSTANCE.primaryAbi());
            if (importedLibrary != null) {
                try {
                    System.load(importedLibrary.getAbsolutePath());
                    sHaveGestureLib = true;
                } catch (Throwable t) {
                    Log.w(TAG, "Could not load verified gesture library", t);
                }
            }
        }

        // Some Android system images already provide Google's compatible gesture library.
        if (!sHaveGestureLib) {
            try {
                System.loadLibrary(JNI_LIB_NAME_GOOGLE);
                sHaveGestureLib = true;
            } catch (UnsatisfiedLinkError ul) {
                Log.w(TAG, "Could not load system gesture library " + JNI_LIB_NAME_GOOGLE, ul);
            }
        }

        // The packaged AOSP library provides normal typing and dictionaries, but not gesture
        // recognition. It is always the final fallback.
        if (!sHaveGestureLib) {
            try {
                System.loadLibrary(JNI_LIB_NAME);
            } catch (UnsatisfiedLinkError ul) {
                Log.w(TAG, "Could not load native library " + JNI_LIB_NAME, ul);
            }
        }
    }

    private JniUtils() {
        // This utility class is not publicly instantiable.
    }

    public static void loadNativeLibrary() {
        // Ensures the static initializer is called
    }
}
