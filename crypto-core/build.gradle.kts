import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.Internal

abstract class SyncNativeLibrariesTask : Sync() {
    @get:Internal
    abstract val outputDirectory: DirectoryProperty
}

plugins {
    id("com.android.library")
}

val pinnedNdkVersion = "28.0.13004108"
val pinnedNdkDirectory = androidComponents.sdkComponents.sdkDirectory.get().asFile.resolve("ndk/$pinnedNdkVersion")
val rawRustJniLibs = layout.buildDirectory.dir("rustJniRaw")
val packagedJniLibs = layout.buildDirectory.dir("generated/jniLibs")

android {
    namespace = "org.cipherboard.cryptocore"
    compileSdk = 36
    ndkVersion = pinnedNdkVersion

    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isJniDebuggable = false
        }
        debug {
            isJniDebuggable = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = true
        // Versions intentionally match the parent HeliBoard build.
        disable += setOf("AndroidGradlePluginVersion", "NewerVersionAvailable")
    }
}

val buildRust by tasks.registering(Exec::class) {
    group = "build"
    description = "Build the stateless Rust JNI library for the supported Android ABIs."
    inputs.files(fileTree("jni/src"), fileTree("native/src"))
    inputs.files("jni/Cargo.toml", "jni/Cargo.lock", "native/Cargo.toml", "native/Cargo.lock")
    outputs.dir(rawRustJniLibs)
    environment("ANDROID_NDK_HOME", pinnedNdkDirectory.absolutePath)
    workingDir(layout.projectDirectory.dir("jni"))
    commandLine(
        "cargo", "ndk",
        "--target", "arm64-v8a",
        "--target", "x86_64",
        "--platform", "23",
        "--output-dir", rawRustJniLibs.get().asFile.absolutePath,
        "build", "--release", "--locked",
    )
}

val syncNativeLibraries by tasks.registering(SyncNativeLibrariesTask::class) {
    outputDirectory.set(packagedJniLibs)
    dependsOn(buildRust)
    from(rawRustJniLibs) {
        include("**/libcipherboard_crypto_jni.so")
    }
    into(packagedJniLibs)
}

tasks.named("preBuild").configure { dependsOn(syncNativeLibraries) }

androidComponents.onVariants { variant ->
    variant.sources.jniLibs?.addGeneratedSourceDirectory(syncNativeLibraries) { it.outputDirectory }
}

dependencies {
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
