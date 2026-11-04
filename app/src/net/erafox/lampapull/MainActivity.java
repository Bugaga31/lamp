// java | MainActivity.java | Android 7+ (API 24), com.lampavpn.app control-plane | забирает манифест по claim-коду и раскладывает конфиги
package net.erafox.lampapull;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.Base64;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class MainActivity extends Activity {

    private static final String BOOTSTRAP = "https://storage.googleapis.com/assets-nhndd717fa/v1/bootstrap";
    private static final String FALLBACK_HOST = "https://tidewaterworks.com:21087";
    private static final String CAPS = "port-set-1,quic-policy-1,probe-policy-1";
    private static final String BUILD = "174";

    private EditText codeInput;
    private TextView logView;
    private Button pullBtn, shareBtn;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String lastLinks = "";
    private File lastDir = null;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        int pad = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("LAMPA Pull");
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView hint = new TextView(this);
        hint.setText("Код доступа из оплаты. Приложение само зарегистрирует устройство, вытянет манифест и разложит конфиги.");
        hint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        hint.setPadding(0, dp(6), 0, dp(12));
        root.addView(hint);

        codeInput = new EditText(this);
        codeInput.setHint("LMP-XXXX-XXXX-XXXX");
        codeInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);
        codeInput.setSingleLine(true);
        root.addView(codeInput);

        pullBtn = new Button(this);
        pullBtn.setText("Забрать конфиги");
        root.addView(pullBtn);

        shareBtn = new Button(this);
        shareBtn.setText("Поделиться ссылками");
        shareBtn.setEnabled(false);
        root.addView(shareBtn);

        ScrollView sc = new ScrollView(this);
        logView = new TextView(this);
        logView.setTextIsSelectable(true);
        logView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setPadding(0, dp(12), 0, 0);
        sc.addView(logView);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(sc, lp);

        setContentView(root);

        pullBtn.setOnClickListener(v -> {
            String code = codeInput.getText().toString();
            if (code.trim().isEmpty()) {
                Toast.makeText(this, "Введи код", Toast.LENGTH_SHORT).show();
                return;
            }
            pullBtn.setEnabled(false);
            logView.setText("");
            new Thread(() -> run(code.trim())).start();
        });

        shareBtn.setOnClickListener(v -> {
            if (lastLinks.isEmpty()) return;
            Intent i = new Intent(Intent.ACTION_SEND);
            i.setType("text/plain");
            i.putExtra(Intent.EXTRA_SUBJECT, "LAMPA links");
            i.putExtra(Intent.EXTRA_TEXT, lastLinks);
            startActivity(Intent.createChooser(i, "Поделиться"));
        });
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    private void log(String s) {
        ui.post(() -> logView.append(s + "\n"));
    }

    // ---------------------------------------------------------------- flow
    private void run(String rawCode) {
        try {
            String code = normalise(rawCode);
            log("код: " + code);

            String host = bootstrapHost();
            log("api: " + host);

            KeyPair kp = keyPair();
            PrivateKey key = kp.getPrivate();
            String spki = Base64.encodeToString(kp.getPublic().getEncoded(), Base64.NO_WRAP);

            JSONObject reg = new JSONObject();
            reg.put("code", code);
            reg.put("brand", "lampa");
            reg.put("pub_key", spki);
            reg.put("attestation", "none");

            log("POST /v1/device/register");
            Reply r = call(host, "POST", "/v1/device/register", reg.toString().getBytes(StandardCharsets.UTF_8), null);
            if (r.status >= 400) {
                log("отказ " + r.status + ": " + r.text());
                throw new RuntimeException(r.text());
            }
            JSONObject rj = new JSONObject(r.text());
            String deviceRef = rj.optString("device_ref", rj.optString("deviceRef", ""));
            String tunnel = rj.optString("tunnel_address", rj.optString("tunnelAddress", ""));
            if (deviceRef.isEmpty()) throw new RuntimeException("нет device_ref в ответе");
            log("device_ref: " + deviceRef);

            String ts = String.valueOf(System.currentTimeMillis() / 1000L);
            String signing = deviceRef + "\nGET\n/v1/device/manifest\n" + ts;
            Signature sg = Signature.getInstance("SHA256withECDSA");
            sg.initSign(key);
            sg.update(signing.getBytes(StandardCharsets.UTF_8));
            String sigB64 = Base64.encodeToString(sg.sign(), Base64.NO_WRAP);

            String[] hk = {"X-Lampa-Device", deviceRef, "X-Lampa-Timestamp", ts,
                    "X-Lampa-Signature", sigB64, "X-Lampa-Platform", "android",
                    "X-Lampa-Build", BUILD, "X-Lampa-Caps", CAPS,
                    "X-Lampa-Install", installId(), "Accept-Language", "ru-RU"};

            log("GET /v1/device/manifest");
            Reply mr = call(host, "GET", "/v1/device/manifest", null, hk);
            int guard = 0;
            while (mr.status < 400 && guard < 6 && hasNeedMore(mr.text())) {
                mr = call(host, "GET", "/v1/device/manifest?need_more=1", null, hk);
                guard++;
            }
            if (mr.status >= 400) {
                log("манифест отказ " + mr.status + ": " + mr.text());
                throw new RuntimeException(mr.text());
            }
            String manifestText = mr.text();
            JSONObject m = new JSONObject(manifestText);

            File dir = new File(getExternalFilesDir(null),
                    "LAMPA-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date()));
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
            write(new File(dir, "manifest.json"), manifestText);

            int n = export(m, dir, tunnel);
            log("готово: " + dir.getAbsolutePath());
            log("файлов: " + n);

            String links = readText(new File(dir, "links.txt"));
            lastLinks = links;
            lastDir = dir;

            ui.post(() -> {
                shareBtn.setEnabled(!links.isEmpty());
                pullBtn.setEnabled(true);
            });
        } catch (Exception e) {
            log("ошибка: " + e.getMessage());
            ui.post(() -> pullBtn.setEnabled(true));
        }
    }

    private static boolean hasNeedMore(String s) {
        return s != null && (s.contains("\"needMore\":true") || s.contains("\"need_more\":true"));
    }

    // ---------------------------------------------------------------- keys
    private KeyPair keyPair() throws Exception {
        String priv = getSharedPreferences("k", MODE_PRIVATE).getString("ec", null);
        String pub = getSharedPreferences("k", MODE_PRIVATE).getString("ecpub", null);
        KeyFactory kf = KeyFactory.getInstance("EC");
        if (priv != null && pub != null) {
            PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(priv, Base64.NO_WRAP)));
            java.security.PublicKey pk = kf.generatePublic(
                    new java.security.spec.X509EncodedKeySpec(Base64.decode(pub, Base64.NO_WRAP)));
            return new KeyPair(pk, sk);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        getSharedPreferences("k", MODE_PRIVATE).edit()
                .putString("ec", Base64.encodeToString(kp.getPrivate().getEncoded(), Base64.NO_WRAP))
                .putString("ecpub", Base64.encodeToString(kp.getPublic().getEncoded(), Base64.NO_WRAP))
                .apply();
        return kp;
    }

    private String wgPrivate() {
        String s = getSharedPreferences("k", MODE_PRIVATE).getString("wg", null);
        if (s != null) return s;
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        s = Base64.encodeToString(seed, Base64.NO_WRAP);
        getSharedPreferences("k", MODE_PRIVATE).edit().putString("wg", s).apply();
        return s;
    }

    private String installId() {
        String s = getSharedPreferences("k", MODE_PRIVATE).getString("install", null);
        if (s != null) return s;
        long t = System.currentTimeMillis();
        long rnd = 100000000000L + (long) (new SecureRandom().nextDouble() * 899999999999L);
        s = t + "-" + rnd;
        getSharedPreferences("k", MODE_PRIVATE).edit().putString("install", s).apply();
        return s;
    }

    private static String normalise(String raw) {
        StringBuilder sb = new StringBuilder();
        for (char c : raw.toUpperCase(Locale.ROOT).toCharArray()) {
            if (Character.isLetterOrDigit(c)) sb.append(c);
        }
        String t = sb.toString();
        if (t.length() < 14) return raw.trim().toUpperCase(Locale.ROOT);
        String prefix = t.substring(0, t.length() - 12);
        String payload = t.substring(t.length() - 12);
        return prefix + "-" + payload.substring(0, 4) + "-" + payload.substring(4, 8) + "-" + payload.substring(8, 12);
    }

    // ---------------------------------------------------------------- net
    private String bootstrapHost() {
        try {
            URL u = new URL(BOOTSTRAP);
            HttpURLConnection c = (HttpURLConnection) u.openConnection();
            c.setConnectTimeout(15000);
            c.setReadTimeout(15000);
            String tok = readAll(c.getInputStream()).trim();
            String[] parts = tok.split("\\.");
            if (parts.length >= 2) {
                byte[] p = Base64.decode(parts[1], Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
                JSONObject j = new JSONObject(new String(p, StandardCharsets.UTF_8));
                JSONArray eps = j.optJSONArray("endpoints");
                if (eps != null && eps.length() > 0) {
                    return eps.getJSONObject(0).getString("url");
                }
            }
        } catch (Exception e) {
            log("bootstrap: " + e.getMessage());
        }
        return FALLBACK_HOST;
    }

    static class Reply {
        int status;
        String body;
        String text() { return body == null ? "" : body; }
    }

    private Reply call(String host, String method, String path, byte[] body, String[] headers) throws Exception {
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, new SecureRandom());

        HttpURLConnection c = (HttpURLConnection) new URL(host + path).openConnection();
        if (c instanceof HttpsURLConnection) {
            ((HttpsURLConnection) c).setSSLSocketFactory(sc.getSocketFactory());
            ((HttpsURLConnection) c).setHostnameVerifier((h, s) -> true);
        }
        c.setRequestMethod(method);
        c.setConnectTimeout(20000);
        c.setReadTimeout(30000);
        c.setRequestProperty("Content-Type", "application/json");
        if (headers != null) {
            for (int i = 0; i + 1 < headers.length; i += 2) c.setRequestProperty(headers[i], headers[i + 1]);
        }
        if (body != null) {
            c.setDoOutput(true);
            try (OutputStream os = c.getOutputStream()) { os.write(body); }
        }
        Reply r = new Reply();
        r.status = c.getResponseCode();
        InputStream is = r.status >= 400 ? c.getErrorStream() : c.getInputStream();
        r.body = is == null ? "" : readAll(is);
        return r;
    }

    private static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
        is.close();
        return new String(bo.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String readText(File f) {
        try (InputStream is = new java.io.FileInputStream(f)) { return readAll(is); }
        catch (Exception e) { return ""; }
    }

    private static void write(File f, String s) {
        try (FileOutputStream o = new FileOutputStream(f)) {
            o.write(s.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {}
    }

    // ---------------------------------------------------------------- export
    private static String s(JSONObject o, String... keys) {
        for (String k : keys) {
            if (o.has(k) && !o.isNull(k)) {
                String v = o.optString(k, null);
                if (v != null) return v;
            }
        }
        return "";
    }

    private int export(JSONObject m, File dir, String tunnel) {
        int count = 0;
        String wgPriv = wgPrivate();

        JSONArray groups = m.optJSONArray("egressGroups");
        if (groups == null) groups = m.optJSONArray("egress_groups");
        if (groups != null) {
            for (int i = 0; i < groups.length(); i++) {
                JSONObject g = groups.optJSONObject(i);
                if (g == null) continue;
                String ref = s(g, "ref");
                String addr = s(g, "address");
                String port = s(g, "port");
                String key = s(g, "serverKey", "server_key");
                int mtu = g.optInt("mtu", 1280);
                int ka = g.optInt("keepalive", 25);

                String inner = tunnel;
                try {
                    JSONObject tr = m.optJSONObject("transports");
                    if (tr != null) {
                        JSONObject gg = tr.optJSONObject("groups");
                        if (gg != null && gg.has(ref)) {
                            Object v = gg.get(ref);
                            if (v instanceof JSONObject) inner = s((JSONObject) v, "address");
                            else if (v instanceof String) inner = (String) v;
                        }
                    }
                } catch (Exception ignored) {}

                String conf = "[Interface]\n"
                        + "PrivateKey = " + wgPriv + "\n"
                        + "Address = " + inner + "\n"
                        + "MTU = " + mtu + "\n\n"
                        + "[Peer]\n"
                        + "PublicKey = " + key + "\n"
                        + "Endpoint = " + addr + ":" + port + "\n"
                        + "AllowedIPs = 0.0.0.0/0, ::/0\n"
                        + "PersistentKeepalive = " + ka + "\n";
                write(new File(dir, "wg-" + (ref.isEmpty() ? String.valueOf(i) : ref) + ".conf"), conf);
                count++;
            }
        }

        JSONArray eps = m.optJSONArray("endpoints");
        JSONArray outbounds = new JSONArray();
        JSONArray plain = new JSONArray();
        if (eps != null) {
            for (int i = 0; i < eps.length(); i++) {
                JSONObject ep = eps.optJSONObject(i);
                if (ep == null) continue;
                JSONObject ob = outbound(ep);
                if (ob != null) {
                    outbounds.put(ob);
                    String link = link(ep);
                    if (!link.isEmpty()) plain.put(link);
                }
            }
        }
        try {
            JSONObject box = new JSONObject();
            JSONArray all = new JSONArray();
            JSONObject sel = new JSONObject();
            sel.put("type", "selector");
            sel.put("tag", "proxy");
            JSONArray tags = new JSONArray();
            for (int i = 0; i < outbounds.length(); i++) tags.put(outbounds.getJSONObject(i).optString("tag"));
            sel.put("outbounds", tags);
            all.put(sel);
            for (int i = 0; i < outbounds.length(); i++) all.put(outbounds.getJSONObject(i));
            box.put("outbounds", all);
            write(new File(dir, "sing-box.json"), box.toString(2));
            count++;
        } catch (Exception ignored) {}

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < plain.length(); i++) sb.append(plain.optString(i)).append("\n");
        write(new File(dir, "links.txt"), sb.toString());
        return count + 1;
    }

    private JSONObject outbound(JSONObject ep) {
        try {
            String t = s(ep, "transport");
            String host = s(ep, "host");
            int port = ep.optInt("port");
            String tag = s(ep, "ref");
            JSONObject p = ep.optJSONObject("params");
            if (p == null) p = new JSONObject();

            JSONObject ob = new JSONObject();
            if ("vless-reality".equals(t) || "vless-xhttp".equals(t)) {
                ob.put("type", "vless");
                ob.put("tag", tag);
                ob.put("server", host);
                ob.put("server_port", port);
                ob.put("uuid", s(p, "user_id", "uuid"));
                JSONObject tls = new JSONObject();
                tls.put("enabled", true);
                tls.put("server_name", s(p, "server_name", "sni"));
                JSONObject utls = new JSONObject();
                utls.put("enabled", true);
                utls.put("fingerprint", s(p, "fingerprint").isEmpty() ? "chrome" : s(p, "fingerprint"));
                tls.put("utls", utls);
                if ("vless-reality".equals(t)) {
                    JSONObject re = new JSONObject();
                    re.put("enabled", true);
                    re.put("public_key", s(p, "public_key", "pbk"));
                    re.put("short_id", s(p, "short_id", "sid"));
                    tls.put("reality", re);
                    ob.put("flow", s(p, "flow").isEmpty() ? "xtls-rprx-vision" : s(p, "flow"));
                } else {
                    JSONObject tr = new JSONObject();
                    tr.put("type", "xhttp");
                    tr.put("host", s(p, "host", "server_name"));
                    tr.put("path", s(p, "path").isEmpty() ? "/" : s(p, "path"));
                    tr.put("mode", s(p, "mode").isEmpty() ? "auto" : s(p, "mode"));
                    ob.put("transport", tr);
                }
                ob.put("tls", tls);
            } else if ("ss2022-shadowtls".equals(t)) {
                ob.put("type", "shadowsocks");
                ob.put("tag", tag);
                ob.put("server", host);
                ob.put("server_port", port);
                ob.put("method", s(p, "method"));
                ob.put("password", s(p, "password"));
                ob.put("plugin", "shadow-tls");
                ob.put("plugin_opts", "host=" + s(p, "shadowtls_sni", "sni"));
            } else if ("hysteria2".equals(t) || "tuic".equals(t) || "trojan".equals(t) || "anytls".equals(t)) {
                ob.put("type", t);
                ob.put("tag", tag);
                ob.put("server", host);
                ob.put("server_port", port);
                String pw = s(p, "password");
                if (!pw.isEmpty()) ob.put("password", pw);
                String uuid = s(p, "uuid", "user_id");
                if (!uuid.isEmpty()) ob.put("uuid", uuid);
            } else {
                return null;
            }
            return ob;
        } catch (Exception e) {
            return null;
        }
    }

    private String link(JSONObject ep) {
        try {
            String t = s(ep, "transport");
            String host = s(ep, "host");
            int port = ep.optInt("port");
            String tag = s(ep, "ref");
            JSONObject p = ep.optJSONObject("params");
            if (p == null) return "";
            if ("vless-reality".equals(t)) {
                return "vless://" + s(p, "user_id", "uuid") + "@" + host + ":" + port
                        + "?security=reality&sni=" + s(p, "server_name", "sni")
                        + "&pbk=" + s(p, "public_key", "pbk")
                        + "&sid=" + s(p, "short_id", "sid")
                        + "&fp=" + (s(p, "fingerprint").isEmpty() ? "chrome" : s(p, "fingerprint"))
                        + "&flow=" + (s(p, "flow").isEmpty() ? "xtls-rprx-vision" : s(p, "flow"))
                        + "#" + tag;
            }
            if ("vless-xhttp".equals(t)) {
                return "vless://" + s(p, "user_id", "uuid") + "@" + host + ":" + port
                        + "?type=xhttp&security=tls&sni=" + s(p, "server_name", "sni")
                        + "&path=" + s(p, "path") + "#" + tag;
            }
            if ("hysteria2".equals(t)) {
                return "hysteria2://" + s(p, "password") + "@" + host + ":" + port + "/?sni=" + s(p, "sni") + "#" + tag;
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }
}
