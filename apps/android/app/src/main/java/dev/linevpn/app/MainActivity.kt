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
    private var permissionInFlight = false
    private var permissionRequestID: String? = null
    private val permissionHelp = "Подключение VPN не подтверждено. Если у другого приложения включена «Постоянная VPN», отключите её и «Блокировать соединения без VPN» именно у него в настройках Android. Затем повторите подключение «Сети». Удалять профиль не нужно."
    private val poll = object : Runnable { override fun run() {
        refreshControlUI()
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
        permissionInFlight = state?.getBoolean("vpnPermissionPending") ?: false
        permissionRequestID = state?.getString("vpnPermissionRequest")
        showLauncher()
        handler.post(poll)
        if (!permissionInFlight) prepareVPN()
    }
    private fun showLauncher(message: String = "Android поддерживает один активный VPN в пользовательском профиле. Для переключения на «Сеть» подтвердите подключение. При сбое защищённые соединения не переходят напрямую; защита при остановке процесса зависит от системной блокировки без VPN.") {
        loaded = ""
        disposeWeb()
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), dp(32), dp(24), dp(24)) }
        box.addView(TextView(this).apply { text = "Сеть"; textSize = 32f; setTextColor(0xFF172341.toInt()); isAccessibilityHeading = true })
        box.addView(TextView(this).apply { text = message; textSize = 16f; setTextColor(0xFF58657B.toInt()); setPadding(0, dp(24), 0, dp(24)) })
        box.addView(Button(this).apply { text = "Открыть VPN"; minHeight = dp(48); setOnClickListener { prepareVPN() } })
        box.addView(Button(this).apply { text = "Настройки VPN"; minHeight = dp(48); setOnClickListener { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } })
        // Large system fonts and landscape must not push either action off screen.
        pageContent(ScrollView(this).apply {
            isFillViewport = true
            addView(box, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))
        })
        systemTheme(false)
    }
    private fun refreshControlUI() {
        val url = Mobile.url()
        if (url.isNotEmpty() && loaded != url) showWeb(url)
        else if (url.isEmpty() && loaded.isNotEmpty()) {
            // onRevoke stops the local HTTP server. Keeping its old WebView
            // strands a resumed Activity on an unreachable power button.
            showLauncher("Служба «Сети» остановлена. Возможно, Android переключился на другой VPN. Нажмите «Открыть VPN», чтобы снова подтвердить подключение. Удалять профиль не нужно.")
        }
    }
    override fun onResume() { super.onResume(); refreshControlUI() }
    override fun onSaveInstanceState(state: Bundle) {
        state.putBoolean("vpnPermissionPending", permissionInFlight)
        state.putString("vpnPermissionRequest", permissionRequestID)
        super.onSaveInstanceState(state)
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
    private fun permissionResult(requestID: String, granted: Boolean, message: String) {
        web?.evaluateJavascript("window.lineVpnPermissionResult && window.lineVpnPermissionResult(${JSONObject.quote(requestID)}, $granted, ${JSONObject.quote(message)})", null)
    }
    private fun prepareVPN(requestID: String? = null) {
        if (isFinishing || isDestroyed) return
        if (permissionInFlight) {
            if (requestID != null) permissionResult(requestID, false, "Завершите текущий запрос разрешения Android и повторите включение.")
            return
        }
        permissionInFlight = true
        permissionRequestID = requestID
        try {
            // Consent may have changed since the last launch, including while
            // the WebView stayed open. Never cache a previous grant.
            val intent = VpnService.prepare(this)
            if (intent != null) startActivityForResult(intent, 1) else finishPermission(true)
        } catch (_: Exception) { finishPermission(false) }
    }
    private fun finishPermission(granted: Boolean) {
        val requestID = permissionRequestID
        permissionRequestID = null
        permissionInFlight = false
        if (requestID != null) {
            permissionResult(requestID, granted, if (granted) "" else permissionHelp)
        } else if (granted) {
            try { startForegroundService(Intent(this, LineVpnService::class.java)) }
            catch (_: Exception) { showLauncher("Не удалось запустить службу VPN. Повторите запуск из этого окна.") }
        } else {
            showLauncher(permissionHelp)
        }
    }
    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
        if (request == 1) {
            val granted = try { result == RESULT_OK && VpnService.prepare(this) == null } catch (_: Exception) { false }
            finishPermission(granted)
        }
    }
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
            @JavascriptInterface fun prepareVPN(requestID: String) { runOnUiThread { this@MainActivity.prepareVPN(requestID) } }
            @JavascriptInterface fun notify(raw: String) { try { val e = JSONObject(raw); NativeNotifications.show(this@MainActivity, e.getString("kind"), e.getString("title"), e.getString("message")) } catch (_: Exception) { } }
        }, "LineBridge")
        pageContent(w)
        w.loadUrl(url)
    }
    private fun disposeWeb() {
        web?.let { view ->
            (view.parent as? ViewGroup)?.removeView(view)
            view.removeJavascriptInterface("LineBridge")
            view.destroy()
        }
        web = null
    }
    override fun onDestroy() { handler.removeCallbacks(poll); disposeWeb(); super.onDestroy() }
}
