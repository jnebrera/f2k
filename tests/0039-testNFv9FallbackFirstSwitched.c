/*
  Copyright (C) 2015-2017 Eneo Tecnologia S.L.
  Copyright (C) 2017-2018 Eugenio Pérez.
  Author: Eugenio Perez <eupm90@gmail.com>
  Based on Luca Deri nprobe 6.22 collector

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "f2k.h"

#include "rb_netflow_test.h"

#include <setjmp.h>

#include <cmocka.h>

#define TEMPLATE_ID 259
#define V9_HEADER                                                              \
	.sys_uptime = constexpr_be32toh(12345),                                \
	.unix_secs = constexpr_be32toh(1382364312),                            \
	.flow_sequence = constexpr_be32toh(1142),                              \
	.source_id = constexpr_be32toh(1)

#define WLAN_SSID_LOCAL_WIFI                                                   \
	'l', 'o', 'c', 'a', 'l', '-', 'w', 'i', 'f', 'i', 0x00, 0x00, 0x00,    \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  \
			0x00, 0x00

#define V9_ENTITIES0(X, ip1, ip2, ip3, ip4)                                    \
	X(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7)           \
	X(STA_IPV4_ADDRESS, 4, 0, ip1, ip2, ip3, ip4)                          \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                  \
	X(WLAN_SSID, 33, 0, WLAN_SSID_LOCAL_WIFI)                              \
	X(DIRECTION, 1, 0, 0)                                                  \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603))                           \
	X(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263))                             \
	X(98, 1, 0, 0)                                                         \
	X(195, 1, 0, 0)                                                        \
	X(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

#define V9_ENTITIES(RT, R)                                                     \
	V9_ENTITIES0(RT, 10, 13, 94, 223)                                      \
	V9_ENTITIES0(R, 8, 8, 8, 8)

#define CHECKDATA_BUFFER_1(first_switched, timestamp)                          \
	(struct checkdata_value[]) {                                           \
		{.key = "type", .value = "netflowv9"},                         \
				{.key = "lan_ip", .value = "10.13.94.223"},    \
				{.key = "lan_ip_name", .value = NULL},         \
				{.key = "lan_ip_net", .value = NULL},          \
				{.key = "lan_ip_net_name", .value = NULL},     \
				{.key = "timestamp", .value = timestamp},      \
				{.key = "first_switched",                      \
				 .value = first_switched},                     \
	}

#define CHECKDATA_BUFFER_2(first_switched, timestamp)                          \
	(struct checkdata_value[]) {                                           \
		{.key = "type", .value = "netflowv9"},                         \
				{.key = "lan_ip", .value = "8.8.8.8"},         \
				{.key = "lan_ip_name", .value = NULL},         \
				{.key = "lan_ip_net", .value = "8.8.8.0/24"},  \
				{.key = "lan_ip_net_name",                     \
				 .value = "google8"},                          \
				{.key = "timestamp", .value = timestamp},      \
				{.key = "first_switched",                      \
				 .value = first_switched},                     \
	}

static int
prepare_test_fallback_first_switch0(void **state,
				    int separate_long_flows,
				    const struct checkdata *checkdata,
				    size_t checkdata_size) {
	readOnlyGlobals.separate_long_flows = separate_long_flows;

	static const NF9_TEMPLATE(
			v9Template, V9_HEADER, TEMPLATE_ID, V9_ENTITIES);
	static const NF9_FLOW(v9Flow, V9_HEADER, TEMPLATE_ID, V9_ENTITIES);

#define TEST(config_path,                                                      \
	     mhosts_db_path,                                                   \
	     mrecord,                                                          \
	     mrecord_size,                                                     \
	     checks,                                                           \
	     checks_size)                                                      \
	{                                                                      \
		.config_json_path = config_path,                               \
		.host_list_path = mhosts_db_path,                              \
		.netflow_src_ip = 0x04030201, .record = mrecord,               \
		.record_size = mrecord_size, .checkdata = checks,              \
		.checkdata_size = checks_size                                  \
	}

	const struct test_params test_params[] = {
					[0] = TEST("./tests/"
						   "0039-"
						   "testNFv9FallbackFirstSwitch"
						   "ed.json",
						   "./tests/0009-data/",
						   &v9Template,
						   sizeof(v9Template),
						   NULL,
						   0),

					[1] = TEST(NULL,
						   NULL,
						   &v9Flow,
						   sizeof(v9Flow),
						   checkdata,
						   checkdata_size),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

static int
prepare_test_fallback_first_switch_separate_long_flows(void **state) {
	static const struct checkdata_value checkdata_b1_0[] =
			CHECKDATA_BUFFER_1(NULL, "1382364192");
	static const struct checkdata_value checkdata_b1_1[] =
			CHECKDATA_BUFFER_1(NULL, "1382364252");
	static const struct checkdata_value checkdata_b2_0[] =
			CHECKDATA_BUFFER_2(NULL, "1382364192");
	static const struct checkdata_value checkdata_b2_1[] =
			CHECKDATA_BUFFER_2(NULL, "1382364252");

	static const struct checkdata sl1_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata_b1_1),
			 .checks = checkdata_b1_1},
			{.size = RD_ARRAYSIZE(checkdata_b1_0),
			 .checks = checkdata_b1_0},
			{.size = RD_ARRAYSIZE(checkdata_b2_1),
			 .checks = checkdata_b2_1},
			{.size = RD_ARRAYSIZE(checkdata_b2_0),
			 .checks = checkdata_b2_0},
	};

	return prepare_test_fallback_first_switch0(
			state, 1, sl1_checkdata, RD_ARRAYSIZE(sl1_checkdata));
}

static int prepare_test_fallback_first_switch(void **state) {
	static const struct checkdata_value checkdata_b1[] =
			CHECKDATA_BUFFER_1("1382364192", "1382364312");
	static const struct checkdata_value checkdata_b2[] =
			CHECKDATA_BUFFER_2("1382364192", "1382364312");

	static const struct checkdata sl1_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata_b1),
			 .checks = checkdata_b1},
			{.size = RD_ARRAYSIZE(checkdata_b2),
			 .checks = checkdata_b2},
	};

	return prepare_test_fallback_first_switch0(
			state, 0, sl1_checkdata, RD_ARRAYSIZE(sl1_checkdata));
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(
					testFlow,
					prepare_test_fallback_first_switch_separate_long_flows),
			cmocka_unit_test_setup(
					testFlow,
					prepare_test_fallback_first_switch),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
