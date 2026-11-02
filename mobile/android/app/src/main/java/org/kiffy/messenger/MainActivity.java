package org.kiffy.messenger;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {

    private WebView webView;
    private Vibrator vibrator;
    private final ExecutorService httpExecutor = Executors.newCachedThreadPool();
    private static final Map<String, Map<String, String>> cookieStore = new ConcurrentHashMap<>();

    @SuppressLint({"SetJavaScriptEnabled", "JavascriptInterface"})
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Edge-to-edge system bar styling
        WindowStyler.apply(this);

        vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);

        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(false);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        }

        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            cookieManager.setAcceptThirdPartyCookies(webView, true);
        }

        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient());

        // Native JavaScript bridge for mobile host, haptics & zero-CORS networking
        webView.addJavascriptInterface(new KiffyBridge(), "AndroidHost");

        // Load mobile chat bundle from bundled assets
        webView.loadUrl("file:///android_asset/app.html");
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        httpExecutor.shutdown();
        super.onDestroy();
    }

    public class KiffyBridge {

        @JavascriptInterface
        public void vibrate(int durationMs) {
            if (vibrator != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator.vibrate(VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE));
                } else {
                    vibrator.vibrate(durationMs);
                }
            }
        }

        @JavascriptInterface
        public void startHostService(int port, String adminPw, String psk) {
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Kiffy Host: порт " + port, Toast.LENGTH_SHORT).show());
        }

        @JavascriptInterface
        public void stopHostService() {
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Kiffy Host остановлен", Toast.LENGTH_SHORT).show());
        }

        /**
         * Native HTTP request engine:
         * Bypasses browser CORS completely, persists cookies across domains,
         * and automatically bypasses anti-bot JS challenges (such as InfinityFree slowAES).
         */
        @JavascriptInterface
        public void httpRequest(final String urlStr, final String method, final String headersJson, final String postBody, final int reqId) {
            httpExecutor.execute(() -> {
                executeNativeHttp(urlStr, method, headersJson, postBody, reqId, 0);
            });
        }
    }

    private void executeNativeHttp(String urlStr, String method, String headersJson, String postBody, int reqId, int retryCount) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            String host = url.getHost();

            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method != null && !method.isEmpty() ? method.toUpperCase() : "GET");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 Chrome/120.0 Mobile");
            conn.setRequestProperty("Accept", "application/json, text/plain, */*");

            // Attach stored cookies
            Map<String, String> hostCookies = cookieStore.get(host);
            if (hostCookies != null && !hostCookies.isEmpty()) {
                StringBuilder cookieHeader = new StringBuilder();
                for (Map.Entry<String, String> e : hostCookies.entrySet()) {
                    if (cookieHeader.length() > 0) cookieHeader.append("; ");
                    cookieHeader.append(e.getKey()).append("=").append(e.getValue());
                }
                conn.setRequestProperty("Cookie", cookieHeader.toString());
            }

            // Custom headers
            if (headersJson != null && !headersJson.isEmpty()) {
                try {
                    JSONObject hdr = new JSONObject(headersJson);
                    Iterator<String> keys = hdr.keys();
                    while (keys.hasNext()) {
                        String k = keys.next();
                        conn.setRequestProperty(k, hdr.getString(k));
                    }
                } catch (Exception ignored) {}
            }

            // Post body
            if (postBody != null && !postBody.isEmpty() && ("POST".equalsIgnoreCase(conn.getRequestMethod()) || "PUT".equalsIgnoreCase(conn.getRequestMethod()))) {
                conn.setDoOutput(true);
                byte[] bytes = postBody.getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bytes);
                    os.flush();
                }
            }

            int code = conn.getResponseCode();

            // Extract set-cookie headers
            List<String> cookies = conn.getHeaderFields().get("Set-Cookie");
            if (cookies != null) {
                Map<String, String> map = cookieStore.computeIfAbsent(host, k -> new ConcurrentHashMap<>());
                for (String c : cookies) {
                    int sc = c.indexOf(';');
                    String pair = sc > 0 ? c.substring(0, sc) : c;
                    int eq = pair.indexOf('=');
                    if (eq > 0) {
                        map.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
                    }
                }
            }

            InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            String responseText = "";
            if (is != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                responseText = sb.toString().trim();
            }

            // Automatic InfinityFree / Byet slowAES anti-bot challenge solving
            if (responseText.contains("slowAES") && retryCount < 2) {
                String cookieVal = solveSlowAes(responseText);
                if (cookieVal != null) {
                    Map<String, String> map = cookieStore.computeIfAbsent(host, k -> new ConcurrentHashMap<>());
                    map.put("__test", cookieVal);
                    // Re-run with solved anti-bot cookie
                    if (conn != null) conn.disconnect();
                    executeNativeHttp(urlStr, method, headersJson, postBody, reqId, retryCount + 1);
                    return;
                }
            }

            final int finalCode = code;
            final String finalResp = responseText;
            sendJsResponse(reqId, finalCode, finalResp, null);

        } catch (Exception e) {
            sendJsResponse(reqId, 0, null, e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private void sendJsResponse(final int reqId, final int code, final String body, final String err) {
        if (webView != null) {
            webView.post(() -> {
                try {
                    JSONObject json = new JSONObject();
                    json.put("id", reqId);
                    json.put("status", code);
                    json.put("body", body != null ? body : "");
                    json.put("err", err != null ? err : "");
                    String js = "if (window.__kiffy_http_cb) { window.__kiffy_http_cb(" + json.toString() + "); }";
                    webView.evaluateJavascript(js, null);
                } catch (Exception ignored) {}
            });
        }
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String solveSlowAes(String html) {
        try {
            Pattern pattern = Pattern.compile("toNumbers\\(\"([0-9a-fA-F]+)\"\\)");
            Matcher matcher = pattern.matcher(html);
            List<String> list = new ArrayList<>();
            while (matcher.find()) {
                list.add(matcher.group(1));
            }
            if (list.size() >= 3) {
                byte[] key = hexToBytes(list.get(0));
                byte[] iv = hexToBytes(list.get(1));
                byte[] ct = hexToBytes(list.get(2));
                SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                byte[] decrypted = cipher.doFinal(ct);
                return bytesToHex(decrypted);
            }
        } catch (Exception ignored) {}
        return null;
    }

    static class WindowStyler {
        static void apply(Activity activity) {
            activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            activity.getWindow().setStatusBarColor(Color.parseColor("#121714"));
            activity.getWindow().setNavigationBarColor(Color.parseColor("#121714"));
        }
    }
}
