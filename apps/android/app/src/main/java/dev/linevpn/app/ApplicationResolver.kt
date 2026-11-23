package dev.linevpn.app

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.system.OsConstants
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.MessageDigest
import org.json.JSONObject
import org.json.JSONArray

// Attribute the actual captured socket. Foreground-app guesses and reverse DNS
// are deliberately not used: neither proves which application opened a socket.
class ApplicationResolver(private val context: Context) {
    fun resolve(network: String, source: String, sourcePort: Long, destination: String, destinationPort: Long): String {
        return try {
            val protocol = when (network) { "tcp" -> OsConstants.IPPROTO_TCP; "udp" -> OsConstants.IPPROTO_UDP; else -> return "" }
            val manager = context.getSystemService(ConnectivityManager::class.java)
            val uid = manager.getConnectionOwnerUid(protocol,
                InetSocketAddress(InetAddress.getByName(source), sourcePort.toInt()),
                InetSocketAddress(InetAddress.getByName(destination), destinationPort.toInt()))
            if (uid < 10000) return ""
            val pm = context.packageManager
            val packages = pm.getPackagesForUid(uid) ?: return ""
            // Shared UIDs do not identify a unique app. Selective VPN access stays denied.
            if (packages.size != 1) return ""
            application(packages[0])?.toString() ?: ""
        } catch (_: Exception) { "" }
    }

    private fun application(name: String): JSONObject? {
        val pm = context.packageManager
        val info = pm.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES)
        val app = info.applicationInfo ?: return null
        // An allowlist is enforced by UID. Never admit another package merely
        // because it shares a UID with an approved package.
        if (app.uid < 10000 || pm.getPackagesForUid(app.uid)?.singleOrNull() != name) return null
        val signatures = info.signingInfo?.apkContentsSigners ?: return null
        if (signatures.isEmpty()) return null
        val signer = signatures.map { digest(it.toByteArray()) }.sorted().joinToString(":")
        var label = pm.getApplicationLabel(app).toString().ifBlank { name }.take(200)
        // Go bounds UTF-8 bytes, not UTF-16 characters. A long localized label
        // must not make the complete installed-app catalogue invalid.
        while (label.toByteArray(Charsets.UTF_8).size > 200) label = label.dropLast(1)
        return JSONObject().put("id", digest(("android\n$name\n$signer").toByteArray(Charsets.UTF_8)))
            .put("name", label).put("path", name).put("platform", "android")
    }

    fun installed(): JSONArray {
        val result = JSONArray()
        val pm = context.packageManager
        for (app in pm.getInstalledApplications(0).sortedBy { it.packageName }) {
            if (pm.checkPermission(android.Manifest.permission.INTERNET, app.packageName) != PackageManager.PERMISSION_GRANTED) continue
            try {
                application(app.packageName)?.let { result.put(it) }
            } catch (_: PackageManager.NameNotFoundException) { /* Uninstalled during enumeration. */ }
        }
        check(result.length() <= 512) { "Слишком много установленных приложений" }
        return result
    }

    fun applyScope(builder: android.net.VpnService.Builder, all: Boolean, applications: String) {
        if (all) return
        val requested = JSONArray(applications)
        check(requested.length() <= 512) { "Слишком много разрешений приложений" }
        // Zero addAllowedApplication calls means ALL applications on Android.
        // The VPN app anchors an empty allowlist; its upstream sockets already
        // use protect(). No foreign package gets access through this anchor.
        builder.addAllowedApplication(context.packageName)
        for (i in 0 until requested.length()) {
            val expected = requested.getJSONObject(i)
            val name = expected.getString("path")
            try {
                val actual = application(name) ?: continue
                if (actual.getString("id") != expected.getString("id")) continue
                builder.addAllowedApplication(name)
            } catch (_: PackageManager.NameNotFoundException) { /* Not currently installed. */ }
        }
    }
    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
}
