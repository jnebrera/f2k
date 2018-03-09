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

#define LOCAL_WIFI_SSID                                                        \
	'l', 'o', 'c', 'a', 'l', '-', 'w', 'i', 'f', 'i', 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

#define NF9_ENTITIES_BASE(X)                                                   \
	X(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223)                             \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                  \
	X(WLAN_SSID, 33, 0, LOCAL_WIFI_SSID)                                   \
	X(DIRECTION, 1, 0, 0)                                                  \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(7603))                           \
	X(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(263))                             \
	X(98, 1, 0, 0)                                                         \
	X(195, 1, 0, 0)                                                        \
	X(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

#define NF9_ENTITIES(RT, R)                                                    \
	RT(STA_MAC_ADDRESS, 6, 0, 0x00, 0x05, 0x69, 0x28, 0xb0, 0xc7)          \
	NF9_ENTITIES_BASE(RT)

#define NF9_BROADCAST_ENTITIES(RT, R)                                          \
	RT(STA_MAC_ADDRESS, 6, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)          \
	NF9_ENTITIES_BASE(RT)

static const struct checkdata_value checkdata1[] = {
		// before load mac vendor database
		{.key = "type", .value = "netflowv9"},
		{.key = "client_mac", .value = "00:05:69:28:b0:c7"},
		{.key = "client_mac_vendor", .value = NULL},
};

static const struct checkdata_value checkdata2[] = {
		// After load mac vendor database
		{.key = "type", .value = "netflowv9"},
		{.key = "client_mac", .value = "00:05:69:28:b0:c7"},
		{.key = "client_mac_vendor", .value = "VMware"},
};

static const struct checkdata_value checkdata3[] = {
		{.key = "type", .value = "netflowv9"},
		{.key = "client_mac", .value = "ff:ff:ff:ff:ff:ff"},
		{.key = "client_mac_vendor", .value = NULL},
};

//////////////
static int prepare_test_nf9_mac(void **state) {
#define TEMPLATE_ID 259
#define V9_HEADER                                                              \
	.sys_uptime = constexpr_be32toh(12345),                                \
	.unix_secs = constexpr_be32toh(1382364130),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.source_id = constexpr_be32toh(1)

	static const NF9_TEMPLATE(
			v9Template, V9_HEADER, TEMPLATE_ID, NF9_ENTITIES);
	static const NF9_FLOW(v9Flow, V9_HEADER, TEMPLATE_ID, NF9_ENTITIES);
	static const NF9_FLOW(v9FlowBroadcast,
			      V9_HEADER,
			      TEMPLATE_ID,
			      NF9_BROADCAST_ENTITIES);

#define TEST(config_path,                                                      \
	     mmac_db_path,                                                     \
	     mrecord,                                                          \
	     mrecord_size,                                                     \
	     checks,                                                           \
	     checks_size)                                                      \
	{                                                                      \
		.config_json_path = config_path,                               \
		.mac_vendor_database_path = mmac_db_path,                      \
		.netflow_src_ip = 0x04030201, .record = mrecord,               \
		.record_size = mrecord_size, .checkdata = checks,              \
		.checkdata_size = checks_size                                  \
	}

	static const struct checkdata checkdata[] = {
					[0] = {.size = RD_ARRAYSIZE(checkdata1),
					       .checks = checkdata1},
					[1] = {.size = RD_ARRAYSIZE(checkdata2),
					       .checks = checkdata2},
					[2] = {.size = RD_ARRAYSIZE(checkdata3),
					       .checks = checkdata3},
	};

	static const struct test_params test_params[] = {
					[0] = TEST("./tests/"
						   "0000-testFlowV5.json",
						   NULL,
						   &v9Template,
						   sizeof(v9Template),
						   NULL,
						   0),

					[1] = TEST(NULL,
						   NULL,
						   &v9Flow,
						   sizeof(v9Flow),
						   &checkdata[0],
						   1),
					[2] = TEST(NULL,
						   "./tests/0008-data/"
						   "mac_vendors",
						   &v9Flow,
						   sizeof(v9Flow),
						   &checkdata[1],
						   1),
					[3] = TEST(NULL,
						   NULL,
						   &v9FlowBroadcast,
						   sizeof(v9FlowBroadcast),
						   &checkdata[2],
						   1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow, prepare_test_nf9_mac),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
