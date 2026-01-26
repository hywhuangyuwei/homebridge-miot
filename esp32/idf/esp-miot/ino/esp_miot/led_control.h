#pragma once

#include <Arduino.h>

void led_control_begin();
void led_control_loop();

// Non-blocking trigger: the blink sequence runs inside led_control_loop().
void trigger_blue_blink();
