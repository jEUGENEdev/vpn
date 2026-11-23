package dev.linevpn.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import org.json.JSONObject;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.io.InputStream;

/** Only in the test APK: an ordinary unbound socket in a separate application. */
public class ScopeProbeReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        PendingResult pending = goAsync();
        new Thread(() -> {
            JSONObject result = new JSONObject();
            try {
                result.put("uid", android.os.Process.myUid());
                ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
                Network active = cm.getActiveNetwork();
                NetworkCapabilities caps = cm.getNetworkCapabilities(active);
                result.put("vpn", caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
                result.put("synthetic_dns", active != null && cm.getLinkProperties(active) != null
                        && cm.getLinkProperties(active).getDnsServers().contains(InetAddress.getByName("172.29.255.2")));
                HttpURLConnection connection = (HttpURLConnection) new URL("http://10.0.2.2:8765/probe").openConnection();
                connection.setConnectTimeout(1500);
                connection.setReadTimeout(1500);
                try (InputStream input = connection.getInputStream()) {
                    java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
                    int value;
                    while (body.size() < 64 && (value = input.read()) != -1) body.write(value);
                    result.put("body", body.toString("UTF-8").trim());
                } finally { connection.disconnect(); }
            } catch (Exception error) {
                try { result.put("error", error.getClass().getSimpleName()); } catch (Exception ignored) { }
            } finally {
                pending.setResultData(result.toString());
                pending.finish();
            }
        }, "scope-probe").start();
    }
}
