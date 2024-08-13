// WiFi Deauthenticator Detector (O_O)
// Version 1.0
//
// This software is licensed under the MIT License.
// See the license file for details.
// part of the code comes from:
// https://github.com/spacehuhn/DeauthDetector

// include necessary libraries
#include <ESP8266WiFi.h>
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define OLED_RESET 0  // GPIO0
Adafruit_SSD1306 display(OLED_RESET);

// include ESP8266 Non-OS SDK functions
extern "C" {
#include "user_interface.h"
}

// ===== SETTINGS ===== //
#define LED 2              /* LED pin (2=built-in LED) */
#define LED_INVERT true    /* Invert HIGH/LOW for LED */
#define SERIAL_BAUD 115200 /* Baudrate for serial communication */
#define CH_TIME 140        /* Scan time (in ms) per channel */
#define PKT_RATE 5         /* Min. packets before it gets recognized as an attack */
#define PKT_TIME 1         /* Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack */

// Channels to scan on (US=1-11, EU=1-13, JAP=1-14)
const short channels[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13/*,14*/ };
const String spin = "-\\|/";

// ===== Runtime variables ===== //
bool ATTACK { false }; //
int cc2 { 0 };                    // Another counter
int cc3 { 0 };                    // Another counter
int ch_index { 0 };               // Current index of channel array
int packet_rate { 0 };            // Deauth packet counter (resets with each update)
int packets_count { 0 };          // Last Deauth packets counts
int attack_counter { 0 };         // Attack counter
int total_attack_counter { 0 };   // Total Attack counter
unsigned long update_time { 0 };  // Last update time
unsigned long ch_time { 0 };      // Last channel hop time

// ===== Sniffer function ===== //
void sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 28) return; // Drop packets without MAC header
  
  byte pkt_type = buf[12]; // second half of frame control field

  // If captured packet is a deauthentication (0xA0) or disassociation (0xC0) frame
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {
    ++packet_rate; // Only count these specific packets
  }
}

void display_string(String input){
  String msg;
  if (ATTACK != true) {
    if (cc3 <= 10){msg = "(o_o)";}
    else if (10 < cc3 and cc3 <= 20){msg = "(O_o)";}
    else if (20 < cc3 and cc3 <= 30){msg = "(O_O)";}
    else if (30 < cc3 and cc3 <= 40){msg = "(o_O)";}
  }
  else{
    msg = "(^v^)";
  }

  msg = msg + "    " + String(spin[cc2]) + "\n\n";
  msg = msg + input + "\n\n";
  msg = msg + "Pkts : " + String(packets_count)+"\n";
  msg = msg + "Attks: " + String(total_attack_counter)+"\n";
  display.setCursor(0,0);
  display.println(msg);
  display.display();
  display.clearDisplay();
}

// ===== Attack detection functions ===== //
void attack_started() {
  digitalWrite(LED, !LED_INVERT); // turn LED on
  ATTACK = true;
  Serial.println("ATTACK DETECTED");
}

void attack_stopped() {
  digitalWrite(LED, LED_INVERT); // turn LED off
  ATTACK = false;
  Serial.println("ATTACK STOPPED");
}

// ===== Setup ===== //
void setup() {
  Serial.begin(SERIAL_BAUD); // Start serial communication
  // initialize with the I2C addr 0x3C (for the 64x48)
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  // Clear the buffer.
  display.clearDisplay();
  // text display tests
  display.setTextSize(1);
  display.setTextColor(WHITE);

  pinMode(LED, OUTPUT); // Enable LED pin
  digitalWrite(LED, LED_INVERT);
  Serial.println("\n");

  sniffer_start();

}

void sniffer_start(){
  WiFi.disconnect();                   // Disconnect from any saved or active WiFi connections
  wifi_set_opmode(STATION_MODE);       // Set device to client/station mode
  wifi_set_promiscuous_rx_cb(sniffer); // Set sniffer function
  wifi_set_channel(channels[0]);       // Set channel
  wifi_promiscuous_enable(true);       // Enable sniffer
  Serial.println("Sniffer started...");
}

void sniffer_stop(){
  wifi_promiscuous_enable(false);
}

// ===== Loop ===== //
void loop() {
  unsigned long current_time = millis();

  // Update attack detection logic based on packet_rate
  if (current_time - update_time >= (sizeof(channels) * CH_TIME)) {
    update_time = current_time;

    // When detected deauth packets exceed the minimum allowed number
    if (packet_rate >= PKT_RATE) {
      ++attack_counter; // Increment attack counter if packet rate is high enough
    } else {
      if (attack_counter >= PKT_TIME) {
        attack_stopped(); // Stop attack if it was ongoing
      }
      attack_counter = 0; // Reset attack counter
    }

    // When attack exceeds minimum allowed time
    if (attack_counter == PKT_TIME) {
      attack_started();
      ++total_attack_counter; // Increment total attack counter
    }

    // Update packet count for display
    packets_count = packet_rate;

    // Reset packet rate
    packet_rate = 0;
  }

  // Update display with attack status
  if (ATTACK) {
    display_string(" Attack!");
  } else {
    display_string(" scanning");
  }

  // Update counters for display animation
  cc2 = (cc2 + 1) % 4;
  cc3 = (cc3 + 1) % 41;

  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time;
    ch_index = (ch_index + 1) % (sizeof(channels) / sizeof(channels[0]));
    wifi_set_channel(channels[ch_index]);
  }
}
