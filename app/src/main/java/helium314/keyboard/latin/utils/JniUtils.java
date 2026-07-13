/*
 * Copyright (C) 2012 The Android Open Source Project
 * modified
 * SPDX-License-Identifier: Apache-2.0 AND GPL-3.0-only
 */

package helium314.keyboard.latin.utils;

public final class JniUtils {
    private static final String TAG = JniUtils.class.getSimpleName();
    public static final String JNI_LIB_NAME = "jni_latinime";

    public static boolean sHaveGestureLib = false;
    static {
        // CipherBoard loads only its APK-packaged native library. Loading a path selected by the
        // user would execute arbitrary code inside the IME and Vault process.
        try {
            System.loadLibrary(JNI_LIB_NAME);
        } catch (UnsatisfiedLinkError ul) {
            Log.w(TAG, "Could not load native library " + JNI_LIB_NAME, ul);
        }
    }

    private JniUtils() {
        // This utility class is not publicly instantiable.
    }

    public static void loadNativeLibrary() {
        // Ensures the static initializer is called
    }
}
