import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.tasks.testing.Test

// Top-level build file where you can add configuration options common to all sub-projects/modules.

buildscript {
    val kotlinVersion = "2.3.21"
    repositories {
        mavenCentral()
        google()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.13.2")
        classpath(kotlin("gradle-plugin", version = kotlinVersion))

        // NOTE: Do not place your application dependencies here; they belong
        // in the individual module build.gradle files
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

// Robolectric 4.17 accesses these OpenJDK internals on JDK 17+.
// Limit the upstream-recommended openings to the three unit-test JVMs.
configure(listOf(project(":app"), project(":pairing"), project(":secure-storage"))) {
    tasks.withType<Test>().configureEach {
        jvmArgs(
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/java.util=ALL-UNNAMED",
            "--add-opens=java.base/java.io=ALL-UNNAMED",
            "--add-opens=java.base/java.net=ALL-UNNAMED",
            "--add-opens=java.base/java.security=ALL-UNNAMED",
            "--add-opens=java.base/java.text=ALL-UNNAMED",
            "--add-opens=java.base/jdk.internal.access=ALL-UNNAMED",
            "--add-opens=java.desktop/java.awt.font=ALL-UNNAMED",
            "--add-opens=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED",
        )
    }
}

// Lock the external dependency graph that can be packaged into any application variant. Build
// plugins are already pinned above and the Rust workspaces use committed Cargo.lock files.
project(":app") {
    val lockedApplicationConfigurations = buildSet {
        add("coreLibraryDesugaring")
        listOf("debug", "debugNoMinify", "nouserlib", "release", "runTests").forEach { variant ->
            add("${variant}AnnotationProcessorClasspath")
            add("${variant}CompileClasspath")
            add("${variant}RuntimeClasspath")
            add("${variant}UnitTestAnnotationProcessorClasspath")
            add("${variant}UnitTestCompileClasspath")
            add("${variant}UnitTestRuntimeClasspath")
        }
        add("debugAndroidTestAnnotationProcessorClasspath")
        add("debugAndroidTestCompileClasspath")
        add("debugAndroidTestRuntimeClasspath")
    }
    dependencyLocking {
        lockMode.set(LockMode.STRICT)
    }
    configurations.configureEach {
        if (name in lockedApplicationConfigurations) {
            resolutionStrategy.activateDependencyLocking()
        }
    }
    tasks.register("resolveApplicationDependencyLocks") {
        group = "build setup"
        description = "Resolves every packageable app graph; run with --write-locks after reviewed updates."
        notCompatibleWithConfigurationCache("dependency lock maintenance resolves configurations explicitly")
        doLast {
            check(gradle.startParameter.isWriteDependencyLocks) {
                "resolveApplicationDependencyLocks must be run with --write-locks"
            }
            lockedApplicationConfigurations.sorted().forEach { configurationName ->
                configurations.getByName(configurationName).incoming.resolutionResult.allComponents
            }
        }
    }
}
