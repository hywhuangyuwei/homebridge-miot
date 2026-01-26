#pragma once

#include <Arduino.h>

// Sends one MiOT "action" UDP packet sequence (handshake + encrypted action).
// Returns true on success.
bool miot_send_action_once();
