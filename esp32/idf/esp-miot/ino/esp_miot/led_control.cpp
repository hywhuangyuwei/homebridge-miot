#include "led_control.h"

#include <Adafruit_NeoPixel.h>

#include "constants.h"

static Adafruit_NeoPixel s_strip(LED_COUNT, LED_PIN, NEO_GRB + NEO_KHZ800);

static uint32_t s_last_rainbow_ms = 0;
static uint16_t s_hue = 0; // 0..359

// Blink state
static volatile bool s_blink_requested = false;
static bool s_blink_active = false;
static uint8_t s_blink_step = 0; // 0..(BLUE_BLINK_TIMES*2-1)
static uint32_t s_blink_deadline_ms = 0;

static void hsv2rgb(uint32_t h, uint32_t s, uint32_t v, uint32_t *r, uint32_t *g, uint32_t *b)
{
  // Matches `main/led_control.c` exactly: HSV(0..359, 0..100, 0..100) -> RGB(0..255)
  h %= 360;
  const uint32_t rgb_max = (uint32_t)(v * 2.55f);
  const uint32_t rgb_min = (uint32_t)(rgb_max * (100 - s) / 100.0f);
  const uint32_t i = h / 60;
  const uint32_t diff = h % 60;
  const uint32_t rgb_adj = (uint32_t)((rgb_max - rgb_min) * diff / 60);

  switch (i)
  {
  case 0:
    *r = rgb_max;
    *g = rgb_min + rgb_adj;
    *b = rgb_min;
    break;
  case 1:
    *r = rgb_max - rgb_adj;
    *g = rgb_max;
    *b = rgb_min;
    break;
  case 2:
    *r = rgb_min;
    *g = rgb_max;
    *b = rgb_min + rgb_adj;
    break;
  case 3:
    *r = rgb_min;
    *g = rgb_max - rgb_adj;
    *b = rgb_max;
    break;
  case 4:
    *r = rgb_min + rgb_adj;
    *g = rgb_min;
    *b = rgb_max;
    break;
  default:
    *r = rgb_max;
    *g = rgb_min;
    *b = rgb_max - rgb_adj;
    break;
  }
}

static inline void set_pixel_rgb(uint8_t r, uint8_t g, uint8_t b)
{
  s_strip.setPixelColor(0, r, g, b);
  s_strip.show();
}

void led_control_begin()
{
  s_strip.begin();
  s_strip.clear();
  // Keep NeoPixel global brightness neutral; we encode brightness via HSV V (like ESP-IDF).
  s_strip.setBrightness(255);
  s_strip.show();

  s_last_rainbow_ms = millis();
  s_hue = 0;
  s_blink_requested = false;
  s_blink_active = false;
  s_blink_step = 0;
  s_blink_deadline_ms = 0;
}

void trigger_blue_blink()
{
  s_blink_requested = true;
}

void led_control_loop()
{
  const uint32_t now_ms = millis();

  // Start blink sequence if requested.
  if (!s_blink_active && s_blink_requested)
  {
    s_blink_requested = false;
    s_blink_active = true;
    s_blink_step = 0;
    s_blink_deadline_ms = 0;
  }

  if (s_blink_active)
  {
    if (s_blink_deadline_ms == 0 || (int32_t)(now_ms - s_blink_deadline_ms) >= 0)
    {
      const bool on_phase = (s_blink_step % 2) == 0;
      if (on_phase)
      {
        set_pixel_rgb(0, 0, 255);
        s_blink_deadline_ms = now_ms + BLUE_BLINK_ON_MS;
      }
      else
      {
        set_pixel_rgb(0, 0, 0);
        s_blink_deadline_ms = now_ms + BLUE_BLINK_OFF_MS;
      }

      s_blink_step++;
      if (s_blink_step >= (uint8_t)(BLUE_BLINK_TIMES * 2))
      {
        s_blink_active = false;
        s_blink_deadline_ms = 0;
      }
    }

    // While blinking, we skip rainbow updates.
    return;
  }

  if ((int32_t)(now_ms - s_last_rainbow_ms) >= (int32_t)RAINBOW_STEP_MS)
  {
    s_last_rainbow_ms = now_ms;

    uint32_t r = 0, g = 0, b = 0;
    hsv2rgb(s_hue, 100, RAINBOW_BRIGHTNESS, &r, &g, &b);
    set_pixel_rgb((uint8_t)r, (uint8_t)g, (uint8_t)b);

    s_hue++;
    if (s_hue >= 360)
    {
      s_hue = 0;
    }
  }
}
