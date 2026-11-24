package dev.linevpn.app;

import android.content.Intent;
import android.app.Activity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.SystemClock;
import android.util.Log;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import static org.junit.Assert.*;
import mobile.Mobile;
import org.json.JSONObject;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** Uses the emulator's actual VpnService/TUN; the host echo server has no secrets. */
public class VpnSmokeTest {
    private static final String PROBE_URL = "http://10.0.2.2:8765/probe";
    private static final String PROBE_BODY = "linevpn-native-ok";
    private android.app.Instrumentation getInstrumentation() { return InstrumentationRegistry.getInstrumentation(); }
    private Network vpnNetwork;
    private JSONObject probeOtherApplication() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<String> result = new java.util.concurrent.atomic.AtomicReference<>();
        Intent probe = new Intent().setComponent(new android.content.ComponentName(
                getInstrumentation().getContext().getPackageName(), "dev.linevpn.app.ScopeProbeReceiver"));
        getInstrumentation().getTargetContext().sendOrderedBroadcast(probe, null, new android.content.BroadcastReceiver() {
            @Override public void onReceive(android.content.Context context, Intent intent) {
                result.set(getResultData()); ready.countDown();
            }
        }, new android.os.Handler(android.os.Looper.getMainLooper()), 0, null, null);
        assertTrue("Separate app probe timed out", ready.await(10, TimeUnit.SECONDS));
        assertNotNull("Separate app receiver did not run", result.get());
        JSONObject state = new JSONObject(result.get());
        assertNotEquals("Probe must run outside the VPN app UID", android.os.Process.myUid(), state.getInt("uid"));
        return state;
    }
    private void revokeRunningVPN() throws Exception {
        android.content.Context context = getInstrumentation().getTargetContext();
        CountDownLatch connected = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<android.os.IBinder> binder = new java.util.concurrent.atomic.AtomicReference<>();
        android.content.ServiceConnection connection = new android.content.ServiceConnection() {
            @Override public void onServiceConnected(android.content.ComponentName name, android.os.IBinder service) {
                binder.set(service); connected.countDown();
            }
            @Override public void onServiceDisconnected(android.content.ComponentName name) { }
        };
        Intent intent = new Intent(context, LineVpnService.class).setAction(android.net.VpnService.SERVICE_INTERFACE);
        assertTrue("Could not bind to own VPN callback", context.bindService(intent, connection, 0));
        try {
            assertTrue("VPN callback unavailable", connected.await(10, TimeUnit.SECONDS));
            android.os.Parcel data = android.os.Parcel.obtain();
            android.os.Parcel reply = android.os.Parcel.obtain();
            try {
                // VpnService.Callback in AOSP uses LAST_CALL_TRANSACTION for onRevoke.
                assertTrue("VPN revocation callback rejected", binder.get().transact(android.os.IBinder.LAST_CALL_TRANSACTION, data, reply, 0));
            } finally { data.recycle(); reply.recycle(); }
        } finally { context.unbindService(connection); }
    }
    private void assertExcludedApplication() throws Exception {
        JSONObject probe = probeOtherApplication();
        assertFalse("Unapproved app sees VPN as its active network", probe.getBoolean("vpn"));
        assertFalse("Unapproved app inherits synthetic DNS", probe.getBoolean("synthetic_dns"));
        assertEquals("Unapproved app lost ordinary connectivity: " + probe, PROBE_BODY, probe.optString("body"));
    }
    private void awaitVPNNetwork(ConnectivityManager connectivity, boolean enabled) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 10000;
        while (SystemClock.elapsedRealtime() < deadline) {
            Network found = null;
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) found = network;
            }
            if ((found != null) == enabled) {
                vpnNetwork = found;
                Log.i("LineVpnSmoke", "Selected VPN network " + found);
                return;
            }
            Thread.sleep(100);
        }
        fail("VPN network did not reach enabled=" + enabled);
    }
    private void assertDirectProbe(String stage, ConnectivityManager connectivity) throws Exception {
        Log.i("LineVpnSmoke", "Direct probe: " + stage + " on " + vpnNetwork);
        try {
            assertEquals(stage, PROBE_BODY, request(PROBE_URL, null, null).trim());
        } catch (Exception | AssertionError failure) {
            // Preserve the original failure. These diagnostics never retry the
            // failed HTTP assertion or print credentials from the local API.
            Log.e("LineVpnSmoke", "Failed network capabilities: " + connectivity.getNetworkCapabilities(vpnNetwork));
            Log.e("LineVpnSmoke", "Failed network links: " + connectivity.getLinkProperties(vpnNetwork));
            JSONObject state = new JSONObject(Mobile.snapshot());
            JSONObject diagnostic = new JSONObject();
            for (String key : new String[]{"status", "vpn_enabled", "tunnel", "traffic_mode", "power_transition", "power_error"})
                diagnostic.put(key, state.opt(key));
            org.json.JSONArray apps = state.getJSONArray("applications");
            for (int i = 0; i < apps.length(); i++) {
                JSONObject app = apps.getJSONObject(i);
                if (app.getString("path").equals(getInstrumentation().getTargetContext().getPackageName())) {
                    for (String key : new String[]{"decision", "last_seen", "target"}) diagnostic.put(key, app.opt(key));
                }
            }
            Log.e("LineVpnSmoke", "Failed direct probe state: " + diagnostic);
            try (DatagramSocket socket = new DatagramSocket()) {
                vpnNetwork.bindSocket(socket);
                socket.setSoTimeout(1000);
                byte[] query = new byte[]{0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
                socket.send(new DatagramPacket(query, query.length, InetAddress.getByName("172.29.255.2"), 53));
                DatagramPacket response = new DatagramPacket(new byte[512], 512);
                socket.receive(response);
                Log.e("LineVpnSmoke", "Independent DNS diagnostic received " + response.getLength() + " bytes");
            } catch (Exception error) { Log.e("LineVpnSmoke", "Independent DNS diagnostic failed: " + error.getClass().getSimpleName()); }
            File[] descriptors = new File("/proc/self/fd").listFiles();
            for (File descriptor : descriptors == null ? new File[0] : descriptors) {
                try {
                    if (android.system.Os.readlink(descriptor.getPath()).contains("tun")) {
                        String info = new String(java.nio.file.Files.readAllBytes(
                                java.nio.file.Paths.get("/proc/self/fdinfo", descriptor.getName())), StandardCharsets.UTF_8);
                        Log.e("LineVpnSmoke", "TUN descriptor " + descriptor.getName() + ": " + info.replace('\n', ' '));
                    }
                } catch (Exception ignored) { /* A descriptor can close during enumeration. */ }
            }
            try (InputStream input = new android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    getInstrumentation().getUiAutomation().executeShellCommand("ip -s link"))) {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096]; int count;
                while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
                Log.e("LineVpnSmoke", "Interface counters: " + output.toString("UTF-8"));
            } catch (Exception error) { Log.e("LineVpnSmoke", "Interface counter diagnostic failed: " + error.getClass().getSimpleName()); }
            throw failure;
        }
    }
    private void power(boolean enabled) throws Exception {
        String local = Mobile.url(); int hash = local.indexOf("#token=");
        request(local.substring(0, hash) + "local/vpn", URLDecoder.decode(local.substring(hash + 7), "UTF-8"),
                new JSONObject().put("enabled", enabled).put("confirm", !enabled).toString());
        JSONObject state = new JSONObject(Mobile.snapshot());
        assertEquals(enabled, state.getBoolean("vpn_enabled"));
        assertEquals(enabled, state.getBoolean("tunnel"));
        assertFalse(state.optBoolean("power_transition"));
        assertEquals("", state.optString("power_error"));
    }
    private String request(String address, String token, String body) throws Exception {
        if (token == null) assertNotNull("Data-plane requests must use the VPN network", vpnNetwork);
        return requestOnNetwork(token == null ? vpnNetwork : null, address, token, body);
    }
    private String requestOnNetwork(Network network, String address, String token, String body) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) (network != null ? network.openConnection(new URL(address)) : new URL(address).openConnection());
        conn.setConnectTimeout(4000); conn.setReadTimeout(4000);
        if (token != null) conn.setRequestProperty("Authorization", "Bearer " + token);
        if (body != null) {
            conn.setRequestMethod("POST"); conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream()) { out.write(body.getBytes(StandardCharsets.UTF_8)); }
        }
        try {
            int status = conn.getResponseCode();
            if (status >= 400) throw new IOException("HTTP " + status);
            try (InputStream in = conn.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] b = new byte[4096]; int n; while ((n = in.read(b)) != -1) out.write(b,0,n);
                return out.toString("UTF-8");
            }
        } finally { conn.disconnect(); }
    }
    private void awaitHostBeforeVPN(ConnectivityManager connectivity) throws Exception {
        // sys.boot_completed and an established TUN do not mean the emulator's
        // underlying network is ready. Verify the fixture before starting VPN;
        // never retry the routing or fail-closed assertions below.
        assertEquals("Preflight must run before the VPN service", "stopped", Mobile.status());
        long deadline = SystemClock.elapsedRealtime() + 30000;
        IOException lastError = null;
        while (SystemClock.elapsedRealtime() < deadline) {
            boolean cellularStillConnected = false;
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                        && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) cellularStillConnected = true;
            }
            if (cellularStillConnected) {
                lastError = new IOException("Fixture still has cellular Internet despite airplane mode");
                Thread.sleep(250);
                continue;
            }
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                if (capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                        || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                try {
                    assertEquals("Host fixture returned unexpected content", PROBE_BODY,
                            requestOnNetwork(network, PROBE_URL, null, null).trim());
                    Log.i("LineVpnSmoke", "Host fixture reachable before VPN on network " + network);
                    return;
                } catch (IOException error) {
                    lastError = error;
                    Log.i("LineVpnSmoke", "Waiting for emulator host connectivity on " + network, error);
                }
                if (SystemClock.elapsedRealtime() >= deadline) break;
            }
            Thread.sleep(250);
        }
        throw new AssertionError("Emulator cannot reach the host fixture before VPN startup", lastError);
    }
    private WebView findWeb(View view) {
        if (view instanceof WebView) return (WebView) view;
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) {
                WebView web = findWeb(group.getChildAt(i));
                if (web != null) return web;
            }
        }
        return null;
    }
    private android.widget.Button findOpenVPN(View view) {
        if (view instanceof android.widget.Button && "Открыть VPN".contentEquals(((android.widget.Button) view).getText())) return (android.widget.Button) view;
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) {
                android.widget.Button button = findOpenVPN(group.getChildAt(i));
                if (button != null) return button;
            }
        }
        return null;
    }
    private void reopenStoppedVPN(Activity activity) throws Exception {
        AtomicBoolean ready = new AtomicBoolean(false);
        long deadline = SystemClock.elapsedRealtime() + 10000;
        while (!ready.get() && SystemClock.elapsedRealtime() < deadline) {
            getInstrumentation().runOnMainSync(() -> {
                View root = activity.getWindow().getDecorView();
                android.widget.Button button = findOpenVPN(root);
                ready.set(findWeb(root) == null && button != null && button.isShown());
            });
            if (!ready.get()) Thread.sleep(100);
        }
        assertTrue("Stopped service left Activity attached to its dead control WebView", ready.get());
        assertEquals("Returning to the launcher must not silently restart VPN", "stopped", Mobile.status());
        getInstrumentation().runOnMainSync(() -> findOpenVPN(activity.getWindow().getDecorView()).performClick());
    }
    private void awaitNativeUI(Activity activity) throws Exception {
        AtomicBoolean ready = new AtomicBoolean(false);
        long deadline = System.currentTimeMillis() + 30000;
        while (!ready.get() && System.currentTimeMillis() < deadline) {
            CountDownLatch result = new CountDownLatch(1);
            getInstrumentation().runOnMainSync(() -> {
                WebView web = findWeb(activity.getWindow().getDecorView());
                if (web == null || !web.isShown() || web.getWidth() == 0) { result.countDown(); return; }
                web.evaluateJavascript("document.readyState === 'complete' && document.body.innerText.toLowerCase().includes('сеть')", value -> {
                    ready.set("true".equals(value) && activity.hasWindowFocus());
                    result.countDown();
                });
            });
            result.await(2, TimeUnit.SECONDS);
            if (!ready.get()) Thread.sleep(250);
        }
        assertTrue("MainActivity must display the loaded client WebView in the foreground", ready.get());
        getInstrumentation().runOnMainSync(() -> {
            WebView web = findWeb(activity.getWindow().getDecorView());
            if (android.os.Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = web.getRootWindowInsets().getInsetsIgnoringVisibility(
                    android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.displayCutout());
                int[] position = new int[2]; web.getLocationOnScreen(position);
                assertTrue("Client overlaps the status bar", position[1] >= safe.top);
                assertTrue("Client overlaps the navigation bar", position[1] + web.getHeight() <= activity.getWindow().getDecorView().getHeight() - safe.bottom);
            }
        });
    }
    private android.graphics.Bitmap captureNativeUI(Activity activity) throws Exception {
        awaitNativeUI(activity);
        CountDownLatch visualReady = new CountDownLatch(1);
        getInstrumentation().runOnMainSync(() -> {
            WebView web = findWeb(activity.getWindow().getDecorView());
            web.postVisualStateCallback(1, new WebView.VisualStateCallback() {
                @Override public void onComplete(long id) {
                    web.invalidate();
                    visualReady.countDown();
                }
            });
        });
        assertTrue("WebView compositor did not prepare the loaded page", visualReady.await(20, TimeUnit.SECONDS));
        long deadline = System.currentTimeMillis() + 30000;
        while (System.currentTimeMillis() < deadline) {
            getInstrumentation().waitForIdleSync();
            android.graphics.Bitmap capture = getInstrumentation().getUiAutomation().takeScreenshot();
            assertNotNull("Native UI screenshot unavailable", capture);
            android.graphics.Bitmap frame = capture.copy(android.graphics.Bitmap.Config.ARGB_8888, false);
            capture.recycle();
            int colored = 0;
            // Exclude system bars. A blank WebView cannot pass merely because its
            // DOM loaded: the client's purple controls must reach the display.
            for (int y = frame.getHeight()/12; y < frame.getHeight()*11/12; y += 12) {
                for (int x = 12; x < frame.getWidth()-12; x += 12) {
                    int pixel = frame.getPixel(x,y);
                    int red = android.graphics.Color.red(pixel), green = android.graphics.Color.green(pixel), blue = android.graphics.Color.blue(pixel);
                    if (Math.max(red,Math.max(green,blue))-Math.min(red,Math.min(green,blue)) > 45) colored++;
                }
            }
            if (colored > 50 && activity.hasWindowFocus()) return frame;
            frame.recycle();
            Thread.sleep(250);
        }
        throw new AssertionError("Client DOM loaded but its visible WebView remained blank");
    }
    @Test public void testNativeTunnelDNSAndFailClosedApproval() throws Exception {
        ConnectivityManager connectivity = getInstrumentation().getTargetContext().getSystemService(ConnectivityManager.class);
        awaitHostBeforeVPN(connectivity);
        Intent intent = new Intent(getInstrumentation().getTargetContext(), MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Activity activity = getInstrumentation().startActivitySync(intent);
        long deadline = System.currentTimeMillis() + 30000;
        while (!"running".equals(Mobile.status()) && System.currentTimeMillis() < deadline) Thread.sleep(200);
        assertEquals("Native VPN service did not start", "running", Mobile.status());
        assertTrue(new JSONObject(Mobile.snapshot()).getBoolean("tunnel"));
        deadline = System.currentTimeMillis() + 10000;
        while (vpnNetwork == null && System.currentTimeMillis() < deadline) {
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpnNetwork = network;
            }
            if (vpnNetwork == null) Thread.sleep(100);
        }
        assertNotNull("VPN network missing",vpnNetwork);
        // Finish the cold WebView/Activity startup before timing packet probes.
        // UI readiness is a required assertion, not a fixed boot delay.
        awaitNativeUI(activity);
        Log.i("LineVpnSmoke", "VPN and client UI ready; starting strict data-plane assertions");

        byte[] query = new byte[]{0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
        try (DatagramSocket socket = new DatagramSocket()) {
            vpnNetwork.bindSocket(socket);
            socket.setSoTimeout(5000);
            socket.send(new DatagramPacket(query,query.length,InetAddress.getByName("172.29.255.2"),53));
            byte[] b = new byte[512]; DatagramPacket response = new DatagramPacket(b,b.length); socket.receive(response);
            assertEquals("DNS transaction",0x12,b[0]&255); assertEquals("A answer",1,b[7]&255);
            assertEquals("Fake IPv4 prefix",198,b[response.getLength()-4]&255);
            assertEquals("Fake IPv4 prefix",18,b[response.getLength()-3]&255);
        }
        assertEquals(PROBE_BODY,request(PROBE_URL,null,null).trim());
        String local = Mobile.url(); int hash = local.indexOf("#token=");
        assertTrue(hash > 0);
        String base = local.substring(0,hash), token = URLDecoder.decode(local.substring(hash+7),"UTF-8");
        assertExcludedApplication();
        String otherID = null;
        org.json.JSONArray inventory = new JSONObject(Mobile.snapshot()).getJSONArray("applications");
        for (int i = 0; i < inventory.length(); i++) {
            JSONObject entry = inventory.getJSONObject(i);
            if (entry.getString("path").equals(getInstrumentation().getContext().getPackageName())) otherID = entry.getString("id");
        }
        assertNotNull("Excluded app must be selectable before sending traffic through TUN", otherID);
        request(base+"local/applications",token,new JSONObject().put("id",otherID).put("decision","trusted").toString());
        JSONObject protectedProbe = probeOtherApplication();
        assertTrue("Approved app still bypasses Android VPN", protectedProbe.getBoolean("vpn"));
        assertFalse("Offline trusted app leaked directly", protectedProbe.has("body"));
        request(base+"local/applications",token,new JSONObject().put("id",otherID).put("decision","denied").toString());
        assertExcludedApplication();
        request(base+"local/traffic-mode",token,"{\"mode\":\"all\"}");
        JSONObject fullProbe = probeOtherApplication();
        assertTrue("Full mode omitted an unapproved app", fullProbe.getBoolean("vpn"));
        assertFalse("Full mode leaked directly", fullProbe.has("body"));
        request(base+"local/traffic-mode",token,"{\"mode\":\"selective\"}");
        assertExcludedApplication();
        awaitVPNNetwork(connectivity, true);
        assertDirectProbe("Selective mode must resume forwarding on the replacement interface", connectivity);
        // Exercise rapid replacement of the OS VPN, including reuse of tunN
        // names. Every transition must work on its first packet probe.
        for (int replacement = 0; replacement < 32; replacement++) {
            request(base+"local/traffic-mode",token,"{\"mode\":\"all\"}");
            awaitVPNNetwork(connectivity, true);
            try { request(PROBE_URL,null,null); fail("Repeated full mode leaked directly"); }
            catch (IOException expected) { }
            request(base+"local/traffic-mode",token,"{\"mode\":\"selective\"}");
            awaitVPNNetwork(connectivity, true);
            assertDirectProbe("Selective forwarding after replacement " + replacement, connectivity);
        }
        JSONObject snapshot = new JSONObject(Mobile.snapshot());
        org.json.JSONArray proposals = snapshot.getJSONArray("requests");
        for (int i=0; i<proposals.length(); i++) assertNotEquals("Healthy direct traffic must not prompt", "10.0.2.2", proposals.getJSONObject(i).getString("target"));
        String applicationID = null;
        org.json.JSONArray applications = snapshot.getJSONArray("applications");
        for (int i=0; i<applications.length(); i++) {
            JSONObject application = applications.getJSONObject(i);
            if (application.getString("path").equals(getInstrumentation().getTargetContext().getPackageName())) applicationID = application.getString("id");
        }
        assertNotNull("VpnService must identify the UID/package owning the probe", applicationID);
        request(base+"local/applications",token,new JSONObject().put("id",applicationID).put("decision","trusted").toString());
        awaitVPNNetwork(connectivity, true);
        try { request(PROBE_URL,null,null); fail("Offline trusted app bypassed VPN"); } catch (IOException expected) { }
        request(base+"local/applications",token,new JSONObject().put("id",applicationID).put("decision","addresses").toString());
        awaitVPNNetwork(connectivity, true);
        assertDirectProbe("Revoking application trust must restore the direct route", connectivity);
        // No server has been configured. Approval must remain saved locally
        // before the API returns an error and retain the rule on disk.
        try { request(base+"local/rules",token,"{\"action\":\"approve\",\"target\":\"10.0.2.2\",\"revision\":0}"); fail("Missing server must fail approval sync"); }
        catch (IOException expected) { }
        assertTrue(new JSONObject(Mobile.snapshot()).getJSONArray("pending_protection").toString().contains("10.0.2.2"));
        // Address rules protect admitted apps; they cannot capture an excluded UID.
        assertExcludedApplication();
        try { request(PROBE_URL,null,null); fail("Offline approved address bypassed VPN"); } catch (IOException expected) { }
        Log.i("LineVpnSmoke", "DNS, direct, application trust, restoration and protected failure passed");
        for (int cycle = 0; cycle < 2; cycle++) {
            power(false);
            awaitVPNNetwork(connectivity, false);
            assertEquals(PROBE_BODY, requestOnNetwork(null, PROBE_URL, null, null).trim());
            Network active = connectivity.getActiveNetwork();
            assertNotNull("No ordinary network after off", active);
            assertFalse("Synthetic DNS survived off", connectivity.getLinkProperties(active).getDnsServers().contains(InetAddress.getByName("172.29.255.2")));
            if (cycle == 0) {
                getInstrumentation().getTargetContext().stopService(new Intent(getInstrumentation().getTargetContext(), LineVpnService.class));
                deadline = System.currentTimeMillis() + 10000;
                while (!"stopped".equals(Mobile.status()) && System.currentTimeMillis() < deadline) Thread.sleep(100);
                assertEquals("stopped", Mobile.status());
                assertEquals(PROBE_BODY, requestOnNetwork(null, PROBE_URL, null, null).trim());
                // Reuse the already-open Activity, as after another VPN revokes
                // this service. No activity recreation or profile deletion.
                reopenStoppedVPN(activity);
                deadline = System.currentTimeMillis() + 10000;
                while (!"running".equals(Mobile.status()) && System.currentTimeMillis() < deadline) Thread.sleep(100);
                assertEquals("running", Mobile.status());
                awaitNativeUI(activity);
                JSONObject off = new JSONObject(Mobile.snapshot());
                assertFalse("Service restart re-enabled VPN", off.getBoolean("vpn_enabled"));
                assertFalse("Off startup created TUN", off.getBoolean("tunnel"));
                awaitVPNNetwork(connectivity, false);
                assertEquals(PROBE_BODY, requestOnNetwork(null, PROBE_URL, null, null).trim());
            }
            power(true);
            awaitVPNNetwork(connectivity, true);
            try { request(PROBE_URL,null,null); fail("Offline re-enable bypassed VPN"); } catch (IOException expected) { }
        }
        Log.i("LineVpnSmoke", "Full VPN off/on, restored system DNS, off restart and offline re-enable passed");
        // Wait for compositor output as well as DOM readiness and foreground focus.
        android.graphics.Bitmap preview = captureNativeUI(activity);
        try (FileOutputStream out = new FileOutputStream(new File(getInstrumentation().getTargetContext().getFilesDir(), "native-preview.png"))) {
            assertTrue(preview.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out));
        } finally { preview.recycle(); }
        // Android keeps a live VpnService bound even after stopService().
        // Exercise the framework's actual revocation Binder callback instead.
        revokeRunningVPN();
        deadline = System.currentTimeMillis() + 10000;
        while (!"stopped".equals(Mobile.status()) && System.currentTimeMillis() < deadline) Thread.sleep(100);
        assertEquals("stopped", Mobile.status());
        awaitVPNNetwork(connectivity, false);
        assertEquals(PROBE_BODY, requestOnNetwork(null, PROBE_URL, null, null).trim());

    }
}
