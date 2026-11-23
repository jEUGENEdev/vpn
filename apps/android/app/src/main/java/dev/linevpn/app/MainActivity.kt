package dev.linevpn.app

import android.app.*
import android.content.*
import android.net.VpnService
import android.os.*
import android.provider.Settings
import android.webkit.*
import android.view.*
import android.graphics.Color
import android.widget.*
import mobile.Mobile
import org.json.JSONObject

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private var web: WebView? = null
    private var loaded = ""
    private var contentRoot: FrameLayout? = null
    private val poll = object : Runnable { override fun run() {
        val url = Mobile.url()
        if (url.isNotEmpty() && loaded != url) showWeb(url)
        handler.postDelayed(this, 1500)
    }}
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        if (Build.VERSION.SDK_INT >= 30) window.setDecorFitsSystemWindows(false)
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Color.TRANSPARENT
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        systemTheme(false)
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 100)
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), dp(32), dp(24), dp(24)) }
        box.addView(TextView(this).apply { text = "Сеть"; textSize = 32f; setTextColor(0xFF172341.toInt()); isAccessibilityHeading = true })
        box.addView(TextView(this).apply { text = "При сбое VPN разрешённые адреса и доверенные приложения блокируются. Прямой доступ для них включается кнопкой «Выключить VPN». Для защиты при остановке приложения включите «Постоянная VPN» и «Блокировать соединения без VPN» в системных настройках."; textSize = 16f; setTextColor(0xFF58657B.toInt()); setPadding(0, dp(24), 0, dp(24)) })
        box.addView(Button(this).apply { text = "Открыть VPN"; minHeight = dp(48); setOnClickListener { prepareVPN() } })
        box.addView(Button(this).apply { text = "Настройки VPN"; minHeight = dp(48); setOnClickListener { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } })
        // Large system fonts and landscape must not push either action off screen.
        pageContent(ScrollView(this).apply {
            isFillViewport = true
            addView(box, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))
        })
        systemTheme(false)
        handler.post(poll)
        prepareVPN()
    }
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density + 0.5f).toInt()
    private fun systemTheme(dark: Boolean) {
        val color = if (dark) 0xFF141D30.toInt() else 0xFFF4F5F8.toInt()
        contentRoot?.setBackgroundColor(color)
        web?.setBackgroundColor(color)
        if (Build.VERSION.SDK_INT >= 30) {
            val mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            window.decorView.windowInsetsController?.setSystemBarsAppearance(if (dark) 0 else mask, mask)
        } else {
            val layout = View.SYSTEM_UI_FLAG_LAYOUT_STABLE or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
            window.decorView.systemUiVisibility = layout or if (dark) 0 else View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        }
    }
    private fun pageContent(view: View) {
        (view.parent as? ViewGroup)?.removeView(view)
        val host = FrameLayout(this).apply {
            setBackgroundColor(0xFFF4F5F8.toInt())
            addView(view, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            setOnApplyWindowInsetsListener { root, insets ->
                if (Build.VERSION.SDK_INT >= 30) {
                    val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime())
                    root.setPadding(safe.left, safe.top, safe.right, safe.bottom)
                    WindowInsets.CONSUMED
                } else {
                    root.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
                    insets.consumeSystemWindowInsets()
                }
            }
        }
        contentRoot = host
        setContentView(host)
        host.requestApplyInsets()
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
            @JavascriptInterface fun theme(dark: Boolean) { runOnUiThread { systemTheme(dark) } }
            @JavascriptInterface fun settings() { runOnUiThread { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } }
            @JavascriptInterface fun notify(raw: String) { try { val e = JSONObject(raw); NativeNotifications.show(this@MainActivity, e.getString("kind"), e.getString("title"), e.getString("message")) } catch (_: Exception) { } }
        }, "LineBridge")
        pageContent(w)
        w.loadUrl(url)
    }
    override fun onDestroy() { handler.removeCallbacks(poll); web?.removeJavascriptInterface("LineBridge"); web?.destroy(); super.onDestroy() }
}
