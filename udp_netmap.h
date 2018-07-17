#pragma once
#include <stdint.h>

using namespace std;

void udp_config(const char* ifname, const char* gateway_ip);

void udp_update(uint32_t current);

void udp_input(uint32_t src_ip, uint16_t src_port, uint16_t dst_port, char* data, uint32_t size);

void udp_output(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, void* data, uint32_t size);
