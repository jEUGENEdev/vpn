package dev.linevpn.app

import android.app.*
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.LinkProperties
import android.os.*
import android.content.pm.ServiceInfo
import mobile.Mobile
import mobile.Protector
import org.json.JSONObject

class LineVpnService : VpnService() {
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var starting = false
    @Volatile private var destroyed = false
    private var lastFailure = 0L
    private val tunnelLock = Any()
    private var retainedTunnel: ParcelFileDescriptor? = null
    private fun releaseTunnel() = synchronized(tunnelLock) {
        retainedTunnel?.close()
        retainedTunnel = null
    }
    private val applicationResolver by lazy { ApplicationResolver(this) }
    private val packagesChanged = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (destroyed || intent.getBooleanExtra(Intent.EXTRA_REPLACING, false) && intent.action == Intent.ACTION_PACKAGE_REMOVED) return
            worker.execute {
                if (!destroyed) try { Mobile.refreshApplications() }
                catch (e: Exception) {
                    android.util.Log.e("LineVPN", "Application scope update failed", e)
                    NativeNotifications.show(this@LineVpnService, "outage", "Не удалось обновить список приложений", "Откройте приложение и повторите запуск VPN.")
                }
            }
        }
    }
    private val seenEvents = linkedSetOf<String>()
    private val monitor = object : Runnable { override fun run() {
        if (destroyed) return
        try {
            Mobile.setGuard(isLockdownEnabled)
            val snapshot = JSONObject(Mobile.snapshot())
            val status = snapshot.optString("status")
            val events = snapshot.optJSONArray("events")
            if (events != null) for (i in 0 until events.length()) {
                val e = events.getJSONObject(i)
                val id = e.getString("at") + ":" + e.getString("id")
                if (seenEvents.add(id)) { NativeNotifications.show(this@LineVpnService, e.getString("kind"), e.getString("title"), e.getString("message")); if (seenEvents.size > 300) seenEvents.remove(seenEvents.first()) }
            }
            val text = when {
                status == "system_blocked" -> "Android блокирует интернет: не удалось запустить прямой режим. Откройте приложение."
                status == "stopped" -> "Служба VPN остановлена. Защита при остановке зависит от блокировки без VPN в Android."
                status == "network_error" -> "Ошибка сети. Откройте приложение для повтора или ручного выключения VPN."
                snapshot.optBoolean("power_transition") -> "Переключаем VPN и сетевые настройки…"
                !snapshot.optBoolean("vpn_enabled", true) -> "VPN выключен. Трафик идёт напрямую."
                snapshot.optBoolean("partial_outage") -> "Сбой части VPN-соединений. Прямое подключение для них запрещено."
                snapshot.optBoolean("protection_blocked") -> "VPN недоступен. Защищённые соединения ожидают восстановления."
                snapshot.optBoolean("sync_pending") -> "Не удалось обновить правила. Работающие VPN-соединения сохранены."
                isLockdownEnabled && snapshot.optString("traffic_mode") != "all" -> "Android блокирует интернет у приложений вне VPN. Проверьте системную блокировку без VPN."
                !isLockdownEnabled -> "VPN работает. Защита при остановке зависит от системной блокировки Android."
                else -> "VPN работает. При сбое защищённые соединения блокируются."
            }

            getSystemService(NotificationManager::class.java).notify(1, notification(text))
        } catch (_: Exception) { }
        main.postDelayed(this, 5000)
    }}
    override fun onCreate() {
        super.onCreate()
        main.post(monitor)
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("protection", "Состояние защиты", NotificationManager.IMPORTANCE_LOW))
        manager.createNotificationChannel(NotificationChannel("events", "Сбои и предложения", NotificationManager.IMPORTANCE_DEFAULT))
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(packagesChanged, filter, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(packagesChanged, filter)
    }
    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, "protection").setSmallIcon(R.drawable.ic_line).setContentTitle("Сеть").setContentText(text).setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true).build()
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (destroyed) return START_NOT_STICKY
        val n = notification("Запускаем VPN. Защищённые соединения ждут VPN.")
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) else startForeground(1, n)
        if (starting || Mobile.status() == "running") return START_STICKY
        starting = true
        worker.execute {
            try {
                Mobile.start(filesDir.absolutePath, object : Protector {
                    override fun checkDisable() {
                        if (isLockdownEnabled) throw IllegalStateException("Сначала отключите «Блокировать соединения без VPN» в системных настройках VPN. Android иначе заблокирует интернет.")
                    }
                    override fun installedApplications(): String = applicationResolver.installed().toString()
                    override fun openTunnel(all: Boolean, applications: String): Long {
                        return synchronized(tunnelLock) {
                        if (destroyed) throw IllegalStateException("VPN service stopped")
                        val builder = Builder().setSession("Сеть").setMtu(1400)
                            .addAddress("172.29.255.1", 30).addAddress("fd04:6c69:6e65:ffff::1", 126)
                            .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("172.29.255.2")
                            .setBlocking(true)
                        applicationResolver.applyScope(builder, all, applications)
                        val descriptor = builder.establish() ?: throw IllegalStateException("VPN permission revoked")
                        // Keep the interface alive if Go fails to start its packet stack.
                        // Only explicit off (without lockdown) releases the retained FD.
                        val previous = retainedTunnel
                        retainedTunnel = descriptor
                        try { previous?.close() } catch (e: Exception) {
                            android.util.Log.w("LineVPN", "Previous tunnel descriptor close failed", e)
                        }
                        // establish() has already replaced the old interface.
                        // Duplication failure must retain the NEW interface too.
                        ParcelFileDescriptor.dup(descriptor.fileDescriptor).detachFd().toLong()
                        }
                    }
                    override fun closeTunnel() { releaseTunnel() }
                    override fun waitTunnelReady(name: String) {
                        val connectivity = getSystemService(ConnectivityManager::class.java)
                        val ready = java.util.concurrent.CountDownLatch(1)
                        val callback = object : ConnectivityManager.NetworkCallback() {
                            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                                // Android sends this after onAvailable, when routes/UID
                                // ranges are ready. Never poll stale synchronous getters
                                // here, or accept a callback from the previous interface.
                                if (properties.interfaceName == name) ready.countDown()
                            }
                        }
                        val request = NetworkRequest.Builder()
                            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                            .addTransportType(NetworkCapabilities.TRANSPORT_VPN).build()
                        // Default Connectivity callback thread is independent of the
                        // main thread, which may currently be waiting on Go's lock.
                        connectivity.registerNetworkCallback(request, callback)
                        try {
                            check(ready.await(10, java.util.concurrent.TimeUnit.SECONDS)) {
                                "Android не подтвердил применение VPN-сети; разрешение не сохранено"
                            }
                        } finally { connectivity.unregisterNetworkCallback(callback) }
                    }
                    override fun deviceName(): String {
                        val model = Build.MODEL?.trim().orEmpty()
                        if (model.isBlank() || model.equals("unknown", true)) return ""
                        val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
                        return if (manufacturer.isBlank() || manufacturer.equals("unknown", true) || model.startsWith(manufacturer, true)) model else "$manufacturer $model"
                    }
                    override fun protect(fd: Long): Boolean = this@LineVpnService.protect(fd.toInt())
                    override fun resolveApplication(network: String, source: String, sourcePort: Long, destination: String, destinationPort: Long): String = applicationResolver.resolve(network, source, sourcePort, destination, destinationPort)
                })
                if (destroyed) { Mobile.stop(); return@execute }
                getSystemService(NotificationManager::class.java).notify(1, notification("Служба запущена. Проверяем выбранный режим VPN."))
            } catch (e: Exception) {
                android.util.Log.e("LineVPN", "Native service startup failed", e)
                Mobile.stop()
                getSystemService(NotificationManager::class.java).notify(1, notification("Сбой службы VPN. Проверьте блокировку без VPN в Android и повторите запуск."))
                val now = System.currentTimeMillis()
                if (now - lastFailure > 15 * 60 * 1000L) { lastFailure = now; NativeNotifications.show(this, "outage", "VPN не запущен", "Не удалось запустить службу. Для защиты при остановке приложения нужна системная блокировка без VPN.") }
                if (!destroyed) main.postDelayed({ if (!destroyed) { starting = false; startForegroundService(Intent(this, LineVpnService::class.java)) } }, 15000)
            } finally { starting = false }
        }
        return START_STICKY
    }
    override fun onRevoke() { destroyed = true; main.removeCallbacksAndMessages(null); NativeNotifications.show(this, "outage", "Разрешение VPN отозвано", "Туннель закрыт. Соединения используют обычную сеть, без VPN-защиты."); Mobile.stop(); releaseTunnel(); stopSelf() }
    override fun onDestroy() { destroyed = true; unregisterReceiver(packagesChanged); main.removeCallbacksAndMessages(null); Mobile.stop(); releaseTunnel(); worker.shutdown(); super.onDestroy() }
}

object NativeNotifications {
    fun show(context: android.content.Context, kind: String, title: String, message: String) {
        val prefs = context.getSharedPreferences("notices", 0)
        val now = System.currentTimeMillis()
        val interval = when (kind) { "suggestion", "application" -> 5 * 60 * 1000L; "recovered" -> 60 * 1000L; else -> 15 * 60 * 1000L }
        if (now - prefs.getLong(kind, 0) < interval) return
        prefs.edit().putLong(kind, now).apply()
        val open = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = Notification.Builder(context, "events").setSmallIcon(R.drawable.ic_line).setContentTitle(title).setContentText(message).setStyle(Notification.BigTextStyle().bigText(message)).setContentIntent(open).setAutoCancel(true).build()
        try { context.getSystemService(NotificationManager::class.java).notify(if (kind == "application") 4 else if (kind == "suggestion") 3 else 2, n) } catch (_: SecurityException) { }
    }
}
