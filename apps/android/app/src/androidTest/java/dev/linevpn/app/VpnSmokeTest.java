package dev.linevpn.app;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
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
    private android.app.Instrumentation getInstrumentation() { return InstrumentationRegistry.getInstrumentation(); }
    private Network vpnNetwork;
    private String request(String address, String token, String body) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) (token == null ? vpnNetwork.openConnection(new URL(address)) : new URL(address).openConnection());
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
    @Test public void testNativeTunnelDNSAndFailClosedApproval() throws Exception {
        Intent intent = new Intent(getInstrumentation().getTargetContext(), MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getInstrumentation().startActivitySync(intent);
        long deadline = System.currentTimeMillis() + 30000;
        while (!"running".equals(Mobile.status()) && System.currentTimeMillis() < deadline) Thread.sleep(200);
        assertEquals("Native VPN service did not start", "running", Mobile.status());
        assertTrue(new JSONObject(Mobile.snapshot()).getBoolean("tunnel"));
        ConnectivityManager connectivity = getInstrumentation().getTargetContext().getSystemService(ConnectivityManager.class);
        deadline = System.currentTimeMillis() + 10000;
        while (vpnNetwork == null && System.currentTimeMillis() < deadline) {
            for (Network network : connectivity.getAllNetworks()) {
                NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) vpnNetwork = network;
            }
            if (vpnNetwork == null) Thread.sleep(100);
        }
        assertNotNull("VPN network missing",vpnNetwork);

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
        assertEquals("linevpn-native-ok",request("http://10.0.2.2:8765/probe",null,null).trim());
        String local = Mobile.url(); int hash = local.indexOf("#token=");
        assertTrue(hash > 0);
        String base = local.substring(0,hash), token = URLDecoder.decode(local.substring(hash+7),"UTF-8");
        // No server has been configured. Approval must nevertheless protect locally
        // before the API returns an error and retain that protection on disk.
        try { request(base+"local/rules",token,"{\"action\":\"approve\",\"target\":\"10.0.2.2\",\"revision\":0}"); fail("Missing server must fail approval sync"); }
        catch (IOException expected) { }
        assertTrue(new JSONObject(Mobile.snapshot()).getJSONArray("pending_protection").toString().contains("10.0.2.2"));
        try { request("http://10.0.2.2:8765/probe",null,null); fail("Approved address escaped directly"); }
        catch (IOException expected) { }
    }
}
