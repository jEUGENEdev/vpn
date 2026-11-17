import groovy.json.JsonSlurper

plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
val lineVpnPackage = JsonSlurper().parse(rootProject.file("../desktop/package.json")) as Map<*, *>
val lineVpnAndroid = lineVpnPackage["linevpn"] as Map<*, *>
android {
    namespace = "dev.linevpn.app"
    compileSdk = 35
    ndkVersion = "28.0.13004108"
    defaultConfig { testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"; applicationId = "dev.linevpn.app"; minSdk = 29; targetSdk = 35; versionCode = (lineVpnAndroid["androidVersionCode"] as Number).toInt(); versionName = lineVpnPackage["version"].toString() + "-preview" }
    signingConfigs {
        getByName("debug") {
            System.getenv("ANDROID_DEBUG_KEYSTORE")?.let { storeFile = file(it) }
        }
        create("release") {
            val path = System.getenv("ANDROID_KEYSTORE")
            if (path != null) { storeFile = file(path); storePassword = System.getenv("ANDROID_STORE_PASSWORD"); keyAlias = System.getenv("ANDROID_KEY_ALIAS"); keyPassword = System.getenv("ANDROID_KEY_PASSWORD") }
        }
    }
    buildTypes {
        getByName("release") { isMinifyEnabled = false; if (System.getenv("ANDROID_KEYSTORE") != null) signingConfig = signingConfigs.getByName("release") }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
 implementation(files("libs/core.aar"))
 androidTestImplementation("androidx.test:runner:1.6.2")
 androidTestImplementation("junit:junit:4.13.2")
}
