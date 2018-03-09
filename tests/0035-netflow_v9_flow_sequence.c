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
	.flow_sequence = constexpr_be32toh(1080),                              \
	.source_id = constexpr_be32toh(1),

#define WLAN_SSID_LOCAL_WIFI                                                   \
	'l', 'o', 'c', 'a', 'l', '-', 'w', 'i', 'f', 'i', 0, 0, 0, 0, 0, 0, 0, \
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

#define NF9_ENTITIES_BASE(X, t_bytes, t_pkts)                                  \
	X(STA_MAC_ADDRESS, 6, 0, 0xb8, 0x17, 0xc2, 0x28, 0xb0, 0xc7)           \
	X(STA_IPV4_ADDRESS, 4, 0, 10, 13, 94, 223)                             \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                  \
	X(WLAN_SSID, 33, 0, WLAN_SSID_LOCAL_WIFI)                              \
	X(DIRECTION, 1, 0, 0)                                                  \
	X(IN_BYTES, 8, 0, UINT32_TO_UINT8_ARR(t_bytes))                        \
	X(IN_PKTS, 8, 0, UINT32_TO_UINT8_ARR(t_pkts))                          \
	X(98, 1, 0, 0)                                                         \
	X(195, 1, 0, 0)                                                        \
	X(WAP_MAC_ADDRESS, 6, 0, 0x58, 0xbf, 0xea, 0x01, 0x5b, 0x40)

#define V9_ENTITIES(RT, R)                                                     \
	NF9_ENTITIES_BASE(RT, 7603, 263)                                       \
	NF9_ENTITIES_BASE(R, 7604, 264)

static const NF9_TEMPLATE(v9Template, V9_HEADER, TEMPLATE_ID, V9_ENTITIES);
static const NF9_FLOW(v9Flow, V9_HEADER, TEMPLATE_ID, V9_ENTITIES);

#define DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(i)                                  \
	static const struct checkdata_value checkdata_values_flow_seq_##i[] =  \
			{                                                      \
					{.key = "flow_sequence", .value = #i}, \
	};
#define CHECKDATA_VALUE_FLOW_SEQUENCE(i) checkdata_values_flow_seq_##i

#define CHECKDATA_VALUE_ENTRY(i)                                               \
	{                                                                      \
		.size = RD_ARRAYSIZE(CHECKDATA_VALUE_FLOW_SEQUENCE(i)),        \
		.checks = CHECKDATA_VALUE_FLOW_SEQUENCE(i)                     \
	}

DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1080);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1081);

static const struct checkdata checkdata_v9_flow_seq[] = {
		CHECKDATA_VALUE_ENTRY(1080), CHECKDATA_VALUE_ENTRY(1081),
};

static int prepare_test_nf9_seq(void **state) {
#define TEST(config_path, mrecord, mrecord_size, checks, checks_sz)            \
	{                                                                      \
		.config_json_path = config_path, .netflow_src_ip = 0x04030201, \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_sz               \
	}

#define TEST_TEMPLATE_FLOW(config_path,                                        \
			   template,                                           \
			   template_size,                                      \
			   flow,                                               \
			   flow_size,                                          \
			   checks,                                             \
			   checks_sz)                                          \
	TEST(config_path, template, template_size, NULL, 0)                    \
	, TEST(NULL, flow, flow_size, checks, checks_sz)

	struct test_params test_params[] = {TEST_TEMPLATE_FLOW(
			"./tests/0000-testFlowV5.json",
			&v9Template,
			sizeof(v9Template),
			&v9Flow,
			sizeof(v9Flow),
			checkdata_v9_flow_seq,
			RD_ARRAYSIZE(checkdata_v9_flow_seq))};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow, prepare_test_nf9_seq),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
