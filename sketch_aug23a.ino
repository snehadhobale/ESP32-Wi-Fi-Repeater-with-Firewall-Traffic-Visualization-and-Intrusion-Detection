/****************************************************
 * ESP32 Firewall Dashboard (Offline, Auth, DoS guard)
 * - LittleFS serves index.html, style.css, script.js, chart.min.js
 * - Basic Auth protects the admin dashboard and APIs
 * - Live traffic chart + MAC table (no IP lookup)
 * - Manual blacklist + auto-block via rate limiting
 ****************************************************/

#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>   // <-- Needed for wifi_sta_list_t & esp_wifi_ap_get_sta_list()
bool isLoggedIn = false;
// ======= Wi-Fi config =======
const char* ssid_STA = "Ace";             // Upstream WiFi (optional)
const char* password_STA = "picklerick";

const char* ssid_AP = "ESP32_Secure_AP";  // ESP32 AP for local dashboard
const char* password_AP = "esp32firewall";

// ======= Admin Basic Auth (dashboard protection) =======
const char* ADMIN_USER = "admin";
const char* ADMIN_PASS = "admin123";      // CHANGE THIS

// ======= Server & Files =======
WebServer server(80);
#define MAX_CLIENTS 8
#define RULES_FILE "/rules.json"
#define LOG_FILE   "/traffic_log.txt"

// ======= DoS/DDoS guard =======
#define WINDOW_SEC 60                // rate window
#define MAX_REQ_PER_WINDOW 30        // threshold before auto-block
#define AUTOBLOCK true

// in-RAM per-IP counters (small + simple)
struct IpCounter {
  String ip;
  unsigned long windowStart; // seconds
  uint16_t count;
};
#define MAX_TRACKED 20
IpCounter counters[MAX_TRACKED];

// ======= JSON docs for rules =======
StaticJsonDocument<4096> rules;

// ======= helpers =======
unsigned long nowSecs() { return millis() / 1000; }

void ensureRulesLoaded() {
  rules.clear();
  if (LittleFS.exists(RULES_FILE)) {
    File f = LittleFS.open(RULES_FILE, "r");
    DeserializationError err = deserializeJson(rules, f);
    f.close();
    if (err) {
      rules.clear();
      rules.createNestedArray("blocked_ips");
    }
  } else {
    rules.createNestedArray("blocked_ips");
  }
}

void saveRules() {
  File f = LittleFS.open(RULES_FILE, "w");
  if (f) {
    serializeJson(rules, f);
    f.flush();
    f.close();
  }
}

bool isBlocked(const String& ip) {
  JsonArray arr = rules["blocked_ips"].as<JsonArray>();
  for (JsonVariant v : arr) {
    if (v.as<String>() == ip) return true;
  }
  return false;
}

void blockIP(const String& ip) {
  if (isBlocked(ip)) return;
  JsonArray arr = rules["blocked_ips"].as<JsonArray>();
  arr.add(ip);
  saveRules();
}

String guessContentType(const String& path) {
  if (path.endsWith(".html")) return "text/html";
  if (path.endsWith(".css"))  return "text/css";
  if (path.endsWith(".js"))   return "application/javascript";
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".png"))  return "image/png";
  if (path.endsWith(".jpg"))  return "image/jpeg";
  if (path.endsWith(".svg"))  return "image/svg+xml";
  return "text/plain";
}

bool handleFileRead(const String& path) {
  String p = path;
  if (p.endsWith("/")) p += "index.html";
  if (!LittleFS.exists(p)) return false;
  File file = LittleFS.open(p, "r");
  server.streamFile(file, guessContentType(p));
  file.close();
  return true;
}

bool requireAuth() {
  if (!isLoggedIn) {
    server.sendHeader("Location", "/login.html");
    server.send(302);  // redirect
    return false;
  }
  return true;
}

void handleLogin() {
  if (server.method() == HTTP_POST) {
    String user = server.arg("user");
    String pass = server.arg("pass");
    if (user == ADMIN_USER && pass == ADMIN_PASS) {
      isLoggedIn = true;
      server.sendHeader("Location", "/");
      server.send(302);
      return;
    } else {
      server.send(200, "text/html", "<h3>Invalid credentials. <a href='/login.html'>Try again</a></h3>");
      return;
    }
  }
  // fallback: serve login.html
  handleFileRead("/login.html");
}
void handleLogoutPage() {
  isLoggedIn = false;
  server.sendHeader("Location", "/login.html");
  server.send(302);
}


void appendLog(const String& ip, const String& status) {
  File f = LittleFS.open(LOG_FILE, FILE_APPEND);
  if (f) {
    f.printf("%s,%lu,%s\n", ip.c_str(), nowSecs(), status.c_str());
    f.close();
  }
}

// Return/allocate an IpCounter slot
IpCounter* getCounterFor(const String& ip) {
  for (int i = 0; i < MAX_TRACKED; i++) {
    if (counters[i].ip == ip) return &counters[i];
  }
  int emptyIdx = -1;
  unsigned long oldestTs = ULONG_MAX; int oldestIdx = 0;
  for (int i = 0; i < MAX_TRACKED; i++) {
    if (counters[i].ip.length() == 0) { emptyIdx = i; break; }
    if (counters[i].windowStart < oldestTs) { oldestTs = counters[i].windowStart; oldestIdx = i; }
  }
  int idx = (emptyIdx >= 0) ? emptyIdx : oldestIdx;
  counters[idx].ip = ip;
  counters[idx].windowStart = nowSecs();
  counters[idx].count = 0;
  return &counters[idx];
}

void recordRequestAndMaybeBlock(const String& ip) {
  IpCounter* c = getCounterFor(ip);
  unsigned long nowS = nowSecs();
  if (nowS - c->windowStart >= WINDOW_SEC) {
    c->windowStart = nowS;
    c->count = 0;
  }
  c->count++;
  if (AUTOBLOCK && c->count > MAX_REQ_PER_WINDOW) {
    blockIP(ip);
    appendLog(ip, "AUTOBLOCK");
  }
}

// ======= HTTP Handlers =======

// Protected dashboard (serves /index.html)
void handleRoot() {
  if (!requireAuth()) return;
  handleFileRead("/index.html");
}

// Serve static assets (browser will reuse auth)
void handleStatic() {
  String uri = server.uri();
  if (!handleFileRead(uri)) {
    server.send(404, "text/plain", "File Not Found");
  }
}

// GET /get-stats -> { "192.168.4.2": { "count": 12, "since": 123456 } ... }
void handleGetStats() {
  if (!requireAuth()) return;

  StaticJsonDocument<1024> doc;
  JsonObject root = doc.to<JsonObject>();
  for (int i = 0; i < MAX_TRACKED; i++) {
    if (counters[i].ip.length() == 0) continue;
    JsonObject o = root.createNestedObject(counters[i].ip);
    o["count"] = counters[i].count;
    o["since"] = counters[i].windowStart;
  }
  String out;
  serializeJson(root, out);
  server.send(200, "application/json", out);
}

// GET /traffic-data -> JSON array of recent log lines (ip, timeSec, status)
void handleTrafficData() {
  if (!requireAuth()) return;

  const int MAX_LINES = 200;
  DynamicJsonDocument arr(8192);
  JsonArray a = arr.to<JsonArray>();

  if (LittleFS.exists(LOG_FILE)) {
    File f = LittleFS.open(LOG_FILE, "r");
    struct Row { String ip; unsigned long t; String st; };
    Row ring[MAX_LINES];
    int idx = 0, total = 0;

    while (f.available()) {
      String line = f.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) continue;
      int c1 = line.indexOf(',');
      int c2 = line.indexOf(',', c1 + 1);
      if (c1 < 0 || c2 < 0) continue;
      String ip = line.substring(0, c1);
      unsigned long t = line.substring(c1 + 1, c2).toInt();
      String st = line.substring(c2 + 1);
      ring[idx] = { ip, t, st };
      idx = (idx + 1) % MAX_LINES;
      total++;
    }
    f.close();

    int start = (total > MAX_LINES) ? (idx) : 0;
    int count = (total > MAX_LINES) ? MAX_LINES : total;
    for (int i = 0; i < count; i++) {
      int k = (start + i) % MAX_LINES;
      JsonObject o = a.createNestedObject();
      o["ip"] = ring[k].ip;
      o["time"] = ring[k].t;
      o["status"] = ring[k].st;
    }
  }
  String out;
  serializeJson(a, out);
  server.send(200, "application/json", out);
}

// POST /add-rule
void handleAddRule() {
  if (!requireAuth()) return;
  String ip = server.arg("ip");
  if (ip.length() == 0) { server.send(400, "text/plain", "missing ip"); return; }
  blockIP(ip);
  appendLog(ip, "MANUAL_BLOCK");
  server.send(200, "text/plain", "ok");
}

// POST /delete-rule
void handleDelRule() {
  if (!requireAuth()) return;
  String ip = server.arg("ip");
  if (ip.length() == 0) { server.send(400, "text/plain", "missing ip"); return; }

  JsonArray arr = rules["blocked_ips"].as<JsonArray>();
  for (int i = 0; i < arr.size(); i++) {
    if (arr[i].as<String>() == ip) { arr.remove(i); break; }
  }
  saveRules();
  appendLog(ip, "MANUAL_UNBLOCK");
  server.send(200, "text/plain", "ok");
}

// GET /rules
void handleRules() {
  if (!requireAuth()) return;
  String out; serializeJson(rules, out);
  server.send(200, "application/json", out);
}

// GET /logout -> force a 401 so browser forgets basic auth
void handleLogout() {
  server.requestAuthentication();
}

// NEW: GET /clients -> live MAC table (no IPs)
void handleClientsMac() {
  if (!requireAuth()) return;

  wifi_sta_list_t list;
  memset(&list, 0, sizeof(list));

  esp_err_t err = esp_wifi_ap_get_sta_list(&list);
  if (err != ESP_OK) {
    server.send(500, "application/json", "{\"error\":\"esp_wifi_ap_get_sta_list failed\"}");
    return;
  }

  StaticJsonDocument<1024> doc;
  JsonArray arr = doc.to<JsonArray>();

  for (int i = 0; i < list.num; i++) {
    const wifi_sta_info_t &st = list.sta[i];
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
            st.mac[0], st.mac[1], st.mac[2], st.mac[3], st.mac[4], st.mac[5]);
    arr.add(String(macStr));
  }

  String out;
  serializeJson(arr, out);
  server.send(200, "application/json", out);
}

// Catch-all
void handleNotFound() {
  String ip = server.client().remoteIP().toString();

  recordRequestAndMaybeBlock(ip);

  if (isBlocked(ip)) {
    appendLog(ip, "BLOCKED");
    server.send(403, "text/plain", "Blocked by firewall.");
    return;
  }

  appendLog(ip, "ACCEPTED");

  if (!handleFileRead(server.uri())) {
    server.send(404, "text/plain", "Not found.");
  }
}

void setup() {
  Serial.begin(115200);
  server.on("/login", HTTP_ANY, handleLogin);
server.on("/logout", HTTP_GET, handleLogoutPage);


  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(ssid_STA, password_STA);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 7000) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();

  bool apOk = WiFi.softAP(ssid_AP, password_AP, 1, 0, MAX_CLIENTS);
  if (apOk) {
    Serial.print("AP up: "); Serial.println(WiFi.softAPIP());
  } else {
    Serial.println("AP start failed!");
  }

  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS mount failed (formatted).");
  }

  ensureRulesLoaded();

  // Routes
  server.on("/", HTTP_GET, handleRoot);                  // Dashboard (protected)
  server.on("/get-stats", HTTP_GET, handleGetStats);     // JSON (protected)
  server.on("/traffic-data", HTTP_GET, handleTrafficData); // JSON (protected)
  server.on("/clients", HTTP_GET, handleClientsMac);     // JSON (protected)  <-- NEW

  server.on("/add-rule", HTTP_POST, handleAddRule);      // Protected
  server.on("/delete-rule", HTTP_POST, handleDelRule);   // Protected
  server.on("/rules", HTTP_GET, handleRules);            // Protected

  server.on("/logout", HTTP_GET, handleLogout);

  // Static assets (LittleFS)
  server.on("/style.css", HTTP_GET, handleStatic);
  server.on("/script.js", HTTP_GET, handleStatic);
  server.on("/chart.min.js", HTTP_GET, handleStatic);

  server.onNotFound(handleNotFound);

  server.begin();
  Serial.println("HTTP server started");
}

void loop() {
  server.handleClient();
  delay(5);
}
