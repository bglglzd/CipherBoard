package helium314.keyboard.latin.utils

/**
 * Compatibility logger for upstream call sites.
 *
 * CipherBoard deliberately discards every payload. Keyboard input, contact names, and other
 * sensitive values must not reach logcat or an in-memory diagnostic buffer in any build type.
 */
@Suppress("UNUSED_PARAMETER")
object Log {
    @JvmStatic
    fun wtf(tag: String?, message: String) = Unit

    @JvmStatic
    fun e(tag: String?, message: String, e: Throwable?) = Unit

    @JvmStatic
    fun e(tag: String?, message: String) = Unit

    @JvmStatic
    fun w(tag: String?, message: String, e: Throwable?) = Unit

    @JvmStatic
    fun w(tag: String?, message: String) = Unit

    @JvmStatic
    fun i(tag: String?, message: String, e: Throwable?) = Unit

    @JvmStatic
    fun i(tag: String?, message: String) = Unit

    @JvmStatic
    fun d(tag: String?, message: String, e: Throwable?) = Unit

    @JvmStatic
    fun d(tag: String?, message: String) = Unit

    @JvmStatic
    fun v(tag: String?, message: String) = Unit
}
