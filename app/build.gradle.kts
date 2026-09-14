import com.android.build.api.variant.ApplicationVariant
import com.android.build.api.artifact.SingleArtifact
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.net.URI
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.zip.ZipInputStream

val cipherboardApplicationId = providers.gradleProperty("cipherboard.applicationId").get()
val cipherboardProductName = providers.gradleProperty("cipherboard.productName").get()
val cipherboardVersionCode = providers.gradleProperty("cipherboard.versionCode").get().toInt()
val cipherboardVersionName = providers.gradleProperty("cipherboard.versionName").get()
val cipherboardArtifactName = providers.gradleProperty("cipherboard.artifactName").get()
val cipherboardBuildToolsVersion = providers.gradleProperty("cipherboard.buildToolsVersion").get()
val generatedLicenseAssets = layout.buildDirectory.dir("generated/cipherboardLicenseAssets")
val generatedVoiceModelAssets = layout.buildDirectory.dir("generated/cipherboardVoiceModelAssets")
val voiceModelCache = rootProject.layout.projectDirectory.dir(".gradle/cipherboard-voice-models")
data class VoiceModelSpec(
    val language: String,
    val archiveRoot: String,
    val url: String,
    val archiveBytes: Long,
    val sha256: String,
)
val voiceModels = listOf(
    VoiceModelSpec(
        language = "en",
        archiveRoot = "vosk-model-small-en-us-0.15",
        url = "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip",
        archiveBytes = 41_205_931,
        sha256 = "30f26242c4eb449f948e42cb302dd7a686cb29a3423a8367f99ff41780942498",
    ),
    VoiceModelSpec(
        language = "ru",
        archiveRoot = "vosk-model-small-ru-0.22",
        url = "https://alphacephei.com/vosk/models/vosk-model-small-ru-0.22.zip",
        archiveBytes = 46_236_750,
        sha256 = "961d5ff98a17f4aa6de69864d0aa71fa5bac682301d2b5d17a3f24c5c99a46d4",
    ),
)

fun File.sha256(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    inputStream().buffered().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

val prepareVoiceModelAssets by tasks.registering {
    group = "build setup"
    description = "Downloads checksum-pinned Vosk models and packages them as offline assets."
    notCompatibleWithConfigurationCache(
        "Downloads and safely expands checksum-pinned model archives into generated assets."
    )
    inputs.property("voiceModels", voiceModels.joinToString("|") { "${it.language}:${it.sha256}" })
    inputs.property("voiceModelMarker", "cipherboard-model.sha256")
    outputs.dir(generatedVoiceModelAssets)
    doLast {
        val cacheDirectory = voiceModelCache.asFile.apply { mkdirs() }
        val outputDirectory = generatedVoiceModelAssets.get().asFile
        project.delete(outputDirectory)
        outputDirectory.mkdirs()

        voiceModels.forEach { spec ->
            val archive = File(cacheDirectory, "${spec.archiveRoot}.zip")
            fun archiveIsTrusted() = archive.isFile
                    && archive.length() == spec.archiveBytes
                    && archive.sha256() == spec.sha256
            if (!archiveIsTrusted()) {
                val temporary = File(cacheDirectory, "${spec.archiveRoot}.zip.part")
                temporary.delete()
                try {
                    URI(spec.url).toURL().openStream().buffered().use { input ->
                        temporary.outputStream().buffered().use { output ->
                            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                            var downloadedBytes = 0L
                            while (true) {
                                val read = input.read(buffer)
                                if (read < 0) break
                                check(downloadedBytes + read <= spec.archiveBytes) {
                                    "Offline voice model exceeds the pinned archive size"
                                }
                                output.write(buffer, 0, read)
                                downloadedBytes += read
                            }
                        }
                    }
                    check(temporary.length() == spec.archiveBytes && temporary.sha256() == spec.sha256) {
                        "Offline voice model failed checksum verification: ${spec.archiveRoot}"
                    }
                    try {
                        Files.move(
                            temporary.toPath(), archive.toPath(),
                            StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING,
                        )
                    } catch (_: AtomicMoveNotSupportedException) {
                        Files.move(temporary.toPath(), archive.toPath(), StandardCopyOption.REPLACE_EXISTING)
                    }
                } catch (failure: Exception) {
                    temporary.delete()
                    throw failure
                }
            }

            val modelOutput = File(outputDirectory, "voice_models/${spec.language}")
            modelOutput.mkdirs()
            var entryCount = 0
            var expandedBytes = 0L
            ZipInputStream(archive.inputStream().buffered()).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    entryCount += 1
                    check(entryCount <= 64) { "Offline voice model archive has too many entries" }
                    val prefix = "${spec.archiveRoot}/"
                    check(entry.name == spec.archiveRoot || entry.name.startsWith(prefix)) {
                        "Offline voice model archive has an unexpected root"
                    }
                    val relativeName = entry.name.removePrefix(prefix)
                    if (relativeName.isNotEmpty()) {
                        val destination = File(modelOutput, relativeName).canonicalFile
                        check(destination.toPath().startsWith(modelOutput.canonicalFile.toPath())) {
                            "Offline voice model archive contains an unsafe path"
                        }
                        if (entry.isDirectory) {
                            destination.mkdirs()
                        } else {
                            destination.parentFile.mkdirs()
                            destination.outputStream().buffered().use { output ->
                                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                                while (true) {
                                    val read = zip.read(buffer)
                                    if (read < 0) break
                                    check(expandedBytes + read <= 250L * 1024L * 1024L) {
                                        "Offline voice model exceeds the expanded-size limit"
                                    }
                                    output.write(buffer, 0, read)
                                    expandedBytes += read
                                }
                            }
                        }
                    }
                    zip.closeEntry()
                }
            }
            check(File(modelOutput, "am/final.mdl").isFile)
            check(File(modelOutput, "conf/model.conf").isFile)
            // Android's asset packager drops dotfiles, so this integrity marker must be visible.
            File(modelOutput, "cipherboard-model.sha256").writeText(spec.sha256, Charsets.US_ASCII)
        }
    }
}
val prepareLicenseAssets by tasks.registering(Sync::class) {
    from(rootProject.files(
        "LICENSE",
        "LICENSE-Apache-2.0",
        "LICENSE-MIT",
        "LICENSE-BlueOak-1.0.0",
        "LICENSE-BSD-3-Clause-NOTICES",
        "LICENSE-CC-BY-SA-4.0",
        "LICENSES.md",
        "THIRD_PARTY_NOTICES.md",
        "UPSTREAM.md",
    )) {
        into("licenses")
    }
    into(generatedLicenseAssets)
}

plugins {
    id("com.android.application")
    kotlin("android")
    kotlin("plugin.serialization") version "2.3.20"
    kotlin("plugin.compose") version "2.3.20"
}

android {
    compileSdk = 36
    buildToolsVersion = cipherboardBuildToolsVersion

    defaultConfig {
        applicationId = cipherboardApplicationId
        minSdk = 23
        targetSdk = 36
        versionCode = cipherboardVersionCode
        versionName = cipherboardVersionName
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        resValue("string", "english_ime_name", cipherboardProductName)
        resValue("string", "ime_settings", "$cipherboardProductName Settings")
        resValue("string", "spell_checker_service_name", "$cipherboardProductName Spell Checker")
        resValue("string", "android_spell_checker_settings", "$cipherboardProductName Spell Checker Settings")
        buildConfigField("String", "PRODUCT_NAME", "\"$cipherboardProductName\"")
        ndk {
            abiFilters.clear()
            abiFilters.add("arm64-v8a")
        }
        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false
            isDebuggable = false
            isJniDebuggable = false
            ndk {
                abiFilters.clear()
                abiFilters += "arm64-v8a"
            }
        }
        create("nouserlib") { // same as release, but does not allow the user to provide a library
            matchingFallbacks += listOf("release")
            isMinifyEnabled = true
            isShrinkResources = false
            isDebuggable = false
            isJniDebuggable = false
            ndk {
                abiFilters.clear()
                abiFilters += "arm64-v8a"
            }
        }
        debug {
            // Shrink unused dependency code while keeping names and bytecode stable for tests.
            isMinifyEnabled = true
            isJniDebuggable = false
            applicationIdSuffix = ".debug"
            testProguardFile("proguard-test-rules.pro")
            ndk {
                abiFilters += "x86_64"
            }
        }
        create("runTests") { // unminified build variant for CI instrumentation
            matchingFallbacks += listOf("debug")
            isMinifyEnabled = false
            isJniDebuggable = false
            ndk {
                abiFilters += "x86_64"
            }
        }
        create("debugNoMinify") { // for faster builds in IDE
            matchingFallbacks += listOf("debug")
            isDebuggable = true
            isMinifyEnabled = false
            isJniDebuggable = false
            signingConfig = signingConfigs.getByName("debug")
            applicationIdSuffix = ".debug"
            ndk {
                abiFilters += "x86_64"
            }
        }

        androidComponents.onVariants { variant: ApplicationVariant ->
            if (variant.buildType == "debug") {
                // got a little too big for GitHub after some dependency upgrades, so we remove the largest dictionary
                variant.androidResources.ignoreAssetsPatterns = listOf("main_ro.dict")
                variant.proguardFiles = emptyList()
                //noinspection ProguardAndroidTxtUsage we intentionally use the "normal" file here
                variant.proguardFiles.add(project.layout.buildDirectory.file(project.buildFile.parent + "/dontoptimize.pro"))
                variant.proguardFiles.add(project.layout.buildDirectory.file(project.buildFile.parent + "/proguard-rules.pro"))
            }
            variant.outputs.forEach { output ->
                if (output is com.android.build.api.variant.impl.VariantOutputImpl) {
                    output.outputFileName = "$cipherboardArtifactName-${defaultConfig.versionName}-${variant.buildType}.apk"
                }
            }
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
        compose = true
    }

    androidResources {
        localeFilters += listOf("en", "ru")
    }

    sourceSets.getByName("main").assets.srcDir(generatedLicenseAssets)
    sourceSets.getByName("main").assets.srcDir(generatedVoiceModelAssets)

    externalNativeBuild {
        ndkBuild {
            path = File("src/main/jni/Android.mk")
        }
    }
    ndkVersion = "28.0.13004108"

    packaging {
        jniLibs {
            // shrinks APK by 3 MB, zipped size unchanged
            useLegacyPackaging = true
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        target {
            compilerOptions {
                jvmTarget.set(JvmTarget.JVM_17)
            }
        }
    }

    // see https://github.com/HeliBorg/HeliBoard/issues/477
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    namespace = "helium314.keyboard.latin"
    lint {
        abortOnError = true
    }
}

tasks.named("preBuild").configure {
    dependsOn(prepareLicenseAssets)
    dependsOn(prepareVoiceModelAssets)
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val mergedManifest = variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)
        val variantName = variant.name
        val variantTaskName = variantName.replaceFirstChar { it.uppercase() }
        val verifyTask = tasks.register("verify${variantTaskName}ForbiddenPermissions") {
            group = "verification"
            description = "Fails when the $variantName merged manifest requests a forbidden permission."
            inputs.file(mergedManifest)
            doLast {
                val manifestText = mergedManifest.get().asFile.readText()
                val requestedPermissions = Regex(
                    """<uses-permission(?:-sdk-\d+)?[^>]*android:name\s*=\s*\"([^\"]+)\""""
                ).findAll(manifestText).map { it.groupValues[1] }.toSet()
                val forbiddenPermissions = setOf(
                    "android.permission.INTERNET",
                    "android.permission.ACCESS_NETWORK_STATE",
                    "android.permission.READ_CONTACTS",
                    "android.permission.WRITE_CONTACTS",
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.QUERY_ALL_PACKAGES",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION",
                )
                val violations = requestedPermissions.intersect(forbiddenPermissions)
                check(violations.isEmpty()) {
                    "Forbidden permissions in $variantName merged manifest: ${violations.sorted().joinToString()}"
                }
            }
        }
        tasks.named("check").configure { dependsOn(verifyTask) }
    }

}

dependencies {
    implementation(project(":crypto-core"))
    implementation(project(":pairing"))
    implementation(project(":secure-storage"))
    implementation("androidx.biometric:biometric:1.1.0")
    // FragmentActivity + Activity Result APIs require Fragment >= 1.3; use the current stable line.
    implementation("androidx.fragment:fragment-ktx:1.8.9")

    // androidx
    implementation("androidx.core:core-ktx:1.17.0") // 1.18.0 requires minSdk 23
    implementation("androidx.recyclerview:recyclerview:1.4.0")
    implementation("androidx.autofill:autofill:1.3.0")
    implementation("androidx.viewpager2:viewpager2:1.1.0")

    // kotlin
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")

    // Offline speech recognition. The Russian and English models are packaged as APK assets.
    implementation("com.alphacephei:vosk-android:0.3.75")

    // compose
    // newer than 2025.11.01 contains androidx.compose.material:material-android:1.10.0, which requires minSdk 23
    // maybe it's possible to use tools:overrideLibrary="androidx.compose.material" as it's not used explicitly, but probably this is just going to crash
    implementation(platform("androidx.compose:compose-bom:2025.11.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    "debugCompileOnly"("androidx.compose.ui:ui-tooling")
    "debugNoMinifyCompileOnly"("androidx.compose.ui:ui-tooling")
    implementation("androidx.navigation:navigation-compose:2.9.8")
    implementation("sh.calvin.reorderable:reorderable:3.1.0") // for easier re-ordering
    implementation("com.github.skydoves:colorpicker-compose:1.1.3") // for user-defined colors

    // test
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.23.0")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:runner:1.7.0")
    testImplementation("androidx.test:core:1.7.0")

    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.concurrent:concurrent-futures-ktx:1.2.0")
    androidTestImplementation("com.google.errorprone:error_prone_annotations:2.36.0")
    "debugImplementation"("androidx.concurrent:concurrent-futures-ktx:1.2.0")
}
