import groovy.json.JsonSlurper

plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
val desktopPackage = JsonSlurper().parse(rootProject.file("../desktop/package.json")) as Map<*, *>
val installerVersion = desktopPackage["version"] as String
require(Regex("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)").matches(installerVersion))
val versionParts = installerVersion.split('.').map { it.toInt() }
require(versionParts[0] <= 255 && versionParts[1] <= 255 && versionParts[2] <= 999)
val installerCode = versionParts[0] * 1_000_000 + versionParts[1] * 1_000 + versionParts[2]
val signingPath = System.getenv("ANDROID_KEYSTORE")?.takeIf { it.isNotBlank() }
android {
    namespace = "dev.linevpn.app"
    compileSdk = 35
    ndkVersion = "28.0.13004108"
    defaultConfig { testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"; applicationId = "dev.linevpn.app"; minSdk = 29; targetSdk = 35; versionCode = installerCode; versionName = installerVersion }
    signingConfigs {
        create("release") {
            if (signingPath != null) { storeFile = file(signingPath); storePassword = System.getenv("ANDROID_STORE_PASSWORD"); keyAlias = System.getenv("ANDROID_KEY_ALIAS"); keyPassword = System.getenv("ANDROID_KEY_PASSWORD") }
        }
    }
    buildTypes {
        getByName("release") { isMinifyEnabled = false; if (signingPath != null) signingConfig = signingConfigs.getByName("release") }
        // Distributable previews and instrumentation must share the persistent key.
        getByName("debug") { if (signingPath != null) signingConfig = signingConfigs.getByName("release") }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
 implementation(files("libs/core.aar"))
 androidTestImplementation("androidx.test:runner:1.6.2")
 androidTestImplementation("junit:junit:4.13.2")
}
