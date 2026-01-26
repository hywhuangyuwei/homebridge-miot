#include <WiFi.h>
#include <WebServer.h>

#include "constants.h"
#include "led_control.h"
#include "miot.h"

static WebServer server(HTTP_PORT);

static void handle_ping()
{
  trigger_blue_blink();
  (void)miot_send_action_once();
  server.send(200, "text/plain", "pong");
}

static void connect_wifi()
{
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  // Simple blocking connect (keeps behavior close to ESP-IDF example).
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(250);
  }
}

void setup()
{
  Serial.begin(115200);
  delay(100);

  led_control_begin();

  connect_wifi();

  server.on("/ping", HTTP_GET, handle_ping);
  server.begin();

  Serial.print("IP: ");
  Serial.println(WiFi.localIP());
}

void loop()
{
  server.handleClient();
  led_control_loop();
}
