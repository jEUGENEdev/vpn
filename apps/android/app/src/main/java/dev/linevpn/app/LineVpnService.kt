package dev.linevpn.app

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.*
import android.content.pm.ServiceInfo
import mobile.Mobile
import mobile.Protector
import org.json.JSONObject

class LineVpnService : VpnService() {
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var starting = false
    private var lastFailure = 0L
    private val applicationResolver by lazy { ApplicationResolver(this) }
    private val seenEvents = linkedSetOf<String>()
    private val monitor = object : Runnable { override fun run() {
        try {
            Mobile.setGuard(isAlwaysOn && isLockdownEnabled)
            val snapshot = JSONObject(Mobile.snapshot())
            val status = snapshot.optString("status")
            val events = snapshot.optJSONArray("events")
            if (events != null) for (i in 0 until events.length()) {
                val e = events.getJSONObject(i)
                val id = e.getString("at") + ":" + e.getString("id")
                if (seenEvents.add(id)) { NativeNotifications.show(this@LineVpnService, e.getString("kind"), e.getString("title"), e.getString("message")); if (seenEvents.size > 300) seenEvents.remove(seenEvents.first()) }
            }
            val text = if (!snapshot.optBoolean("vpn_enabled", true)) "VPN выключен. Весь трафик идёт напрямую." else if (!isAlwaysOn || !isLockdownEnabled) "Включите постоянный VPN и блокировку без VPN в настройках." else if (status == "stopped") "Служба не запущена. Системная блокировка сохраняет защиту." else if (status == "setup" || status == "auth_required") "Войдите в аккаунт для подключения VPN." else if (status == "blocked" || status == "degraded") "Сервер недоступен. Одобренные соединения заблокированы." else "Защита включена. Одобренные адреса — только через VPN."
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
    }
    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, "protection").setSmallIcon(R.drawable.ic_line).setContentTitle("Линия VPN").setContentText(text).setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true).build()
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n = notification("Запускаем защиту. Включите постоянный VPN и блокировку без VPN.")
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) else startForeground(1, n)
        if (starting || Mobile.status() == "running") return START_STICKY
        starting = true
        worker.execute {
            try {
                val descriptor = Builder().setSession("Линия VPN").setMtu(1400)
                    .addAddress("172.29.255.1", 30).addAddress("fd04:6c69:6e65:ffff::1", 126)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("172.29.255.2")
                    .setBlocking(true).establish() ?: throw IllegalStateException("VPN permission revoked")
                // Ownership transfers to Go. Do not close the detached descriptor in Java.
                val fd = descriptor.detachFd()
                Mobile.start(fd.toLong(), filesDir.absolutePath, object : Protector {
                    override fun protect(fd: Long): Boolean = this@LineVpnService.protect(fd.toInt())
                    override fun resolveApplication(network: String, source: String, sourcePort: Long, destination: String, destinationPort: Long): String = applicationResolver.resolve(network, source, sourcePort, destination, destinationPort)
                })
                getSystemService(NotificationManager::class.java).notify(1, notification("Служба запущена. Проверяем выбранный режим VPN."))
            } catch (e: Exception) {
                android.util.Log.e("LineVPN", "Native service startup failed", e)
                Mobile.stop()
                getSystemService(NotificationManager::class.java).notify(1, notification("Ошибка VPN. Проверьте блокировку соединений без VPN."))
                val now = System.currentTimeMillis()
                if (now - lastFailure > 15 * 60 * 1000L) { lastFailure = now; NativeNotifications.show(this, "outage", "VPN не запущен", "Откройте приложение. Включённая системная блокировка предотвращает утечки.") }
                main.postDelayed({ starting = false; startForegroundService(Intent(this, LineVpnService::class.java)) }, 15000)
            } finally { starting = false }
        }
        return START_STICKY
    }
    override fun onRevoke() { NativeNotifications.show(this, "outage", "Разрешение VPN отозвано", "Системная защита отключена пользователем. Одобренные адреса больше не контролируются."); Mobile.stop(); stopSelf() }
    override fun onDestroy() { main.removeCallbacks(monitor); Mobile.stop(); worker.shutdown(); super.onDestroy() }
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
