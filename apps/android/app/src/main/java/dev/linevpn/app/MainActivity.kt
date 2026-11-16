package dev.linevpn.app

import android.app.*
import android.content.*
import android.net.VpnService
import android.os.*
import android.provider.Settings
import android.webkit.*
import android.widget.*
import mobile.Mobile
import org.json.JSONObject

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private var web: WebView? = null
    private var loaded = ""
    private val poll = object : Runnable { override fun run() {
        val url = Mobile.url()
        if (url.isNotEmpty() && loaded != url) showWeb(url)
        handler.postDelayed(this, 1500)
    }}
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 100)
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 70, 40, 30) }
        box.addView(TextView(this).apply { text = "Линия VPN"; textSize = 34f })
        box.addView(TextView(this).apply { text = "Включите постоянный VPN и «Блокировать соединения без VPN» в системных настройках. Это сохраняет защиту при падении службы. Неодобренные адреса выходят напрямую через работающую службу."; textSize = 16f; setPadding(0, 30, 0, 30) })
        box.addView(Button(this).apply { text = "Включить защиту"; setOnClickListener { prepareVPN() } })
        box.addView(Button(this).apply { text = "Настройки постоянного VPN"; setOnClickListener { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } })
        setContentView(box)
        handler.post(poll)
        prepareVPN()
    }
    private fun prepareVPN() { val intent = VpnService.prepare(this); if (intent != null) startActivityForResult(intent, 1) else startForegroundService(Intent(this, LineVpnService::class.java)) }
    override fun onActivityResult(request: Int, result: Int, data: Intent?) { super.onActivityResult(request, result, data); if (request == 1 && result == RESULT_OK) startForegroundService(Intent(this, LineVpnService::class.java)) }
    private fun showWeb(url: String) {
        loaded = url
        val origin = android.net.Uri.parse(url).let { "${it.scheme}://${it.host}:${it.port}/" }
        val w = web ?: WebView(this).also { web = it }
        w.settings.javaScriptEnabled = true
        w.settings.domStorageEnabled = true
        w.settings.allowFileAccess = false
        w.settings.allowContentAccess = false
        w.settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        w.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = !request.url.toString().startsWith(origin)
        }
        w.addJavascriptInterface(object {
            @JavascriptInterface fun settings() { runOnUiThread { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } }
            @JavascriptInterface fun notify(raw: String) { try { val e = JSONObject(raw); NativeNotifications.show(this@MainActivity, e.getString("kind"), e.getString("title"), e.getString("message")) } catch (_: Exception) { } }
        }, "LineBridge")
        setContentView(w)
        w.loadUrl(url)
    }
    override fun onDestroy() { handler.removeCallbacks(poll); web?.removeJavascriptInterface("LineBridge"); web?.destroy(); super.onDestroy() }
}
