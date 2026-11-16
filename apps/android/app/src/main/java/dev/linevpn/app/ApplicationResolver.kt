package dev.linevpn.app

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.system.OsConstants
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.MessageDigest
import org.json.JSONObject

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
            // Shared UIDs do not identify a unique app. Keep address-based rules.
            if (packages.size != 1) return ""
            val name = packages[0]
            val info = pm.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES)
            val signatures = info.signingInfo?.apkContentsSigners ?: return ""
            if (signatures.isEmpty()) return ""
            val signer = signatures.map { digest(it.toByteArray()) }.sorted().joinToString(":")
            val label = info.applicationInfo?.let { pm.getApplicationLabel(it).toString() } ?: name
            JSONObject().put("id", digest(("android\n$name\n$signer").toByteArray(Charsets.UTF_8)))
                .put("name", label.take(200)).put("path", name).put("platform", "android").toString()
        } catch (_: Exception) { "" }
    }
    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
}
