plugins {
    id("com.android.library") version "8.13.2"
    id("org.jetbrains.kotlin.android") version "2.4.21"
}

android {
    namespace = "com.jw1980.passkey"
    compileSdk = 36

    defaultConfig {
        // Credential Manager supports passkeys from Android 9 (API 28).
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
    explicitApi()
}

dependencies {
    api("androidx.credentials:credentials:1.6.0")
    // Passkeys on Android 13 and lower go through Google Play services.
    implementation("androidx.credentials:credentials-play-services-auth:1.6.0")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}
