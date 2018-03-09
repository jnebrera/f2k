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

#define TEST_TEMPLATE_ID 269
#define TEST_IPFIX_HEADER                                                      \
	.unix_secs = constexpr_be32toh(1382637021),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.observation_id = constexpr_be32toh(1),

#define CISCO_HTTP_EMPTY(t_type) 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, t_type
#define IPFIX_ENTITIES_BASE(X, t_bytes, t_pkts)                                \
	X(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44)                                \
	X(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                               \
	X(IP_PROTOCOL_VERSION, 1, 0, 4)                                        \
	X(PROTOCOL, 1, 0, 6)                                                   \
	X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713))                       \
	X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                         \
	X(FLOW_END_REASON, 1, 0, 3)                                            \
	X(BIFLOW_DIRECTION, 1, 0, 1)                                           \
	X(FLOW_SAMPLER_ID, 1, 0, 0)                                            \
	X(TRANSACTION_ID, 8, 0, UINT64_TO_UINT8_ARR(645773089145098240))       \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                  \
	X(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(1))                           \
	X(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(2))                           \
	X(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(3))                           \
	X(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(4))                           \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(t_bytes))                        \
	X(IN_PKTS, 8, 0, UINT64_TO_UINT8_ARR(t_pkts))                          \
	X(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(1373263))                  \
	X(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(1441796))

// clang-format off
#define CHECKDATA_BASE(bytes, pkts)                                            \
	{                                                                      \
		{.key = "type", .value = "netflowv10"},                        \
		{.key = "src", .value = "10.13.122.44"},                       \
		{.key = "dst", .value = "66.220.152.19"},                      \
		{.key = "ip_protocol_version", .value = "4"},                  \
		{.key = "l4_proto", .value = "6"},                             \
		{.key = "src_port", .value = "54713"},                         \
		{.key = "dst_port", .value = "443"},                           \
		{.key = "flow_end_reason", .value = "end of flow"},            \
		{.key = "biflow_direction", .value = "initiator"},             \
		{.key = "application_id", .value = NULL},                      \
		{.key = "sensor_ip", .value = "4.3.2.1"},                      \
		{.key = "sensor_name", .value = "FlowTest"},                   \
		{.key = "bytes", .value = bytes},                              \
		{.key = "pkts", .value = pkts},                                \
		{.key = "first_switched", .value = "1382636953"},              \
		{.key = "timestamp", .value = "1382637021"},                   \
	}
// clang-format on

#define TEST_ENTITIES(RT, R)                                                   \
	IPFIX_ENTITIES_BASE(RT, 68719476736, 31)                               \
	IPFIX_ENTITIES_BASE(R, 31, 68719476736)                                \
	IPFIX_ENTITIES_BASE(R, 68719476767, 68719476736)

static const IPFIX_TEMPLATE(v10Template,
			    TEST_IPFIX_HEADER,
			    TEST_TEMPLATE_ID,
			    TEST_ENTITIES);
static const IPFIX_FLOW(v10Flow,
			TEST_IPFIX_HEADER,
			TEST_TEMPLATE_ID,
			TEST_ENTITIES);

/// Bigger than 32 bits bytes/packets
static int prepare_test_big_bytes(void **state) {
	static const struct checkdata_value checkdata_values_bytes[] =
			CHECKDATA_BASE("68719476736", "31");

	static const struct checkdata_value checkdata_values_pkts[] =
			CHECKDATA_BASE("31", "68719476736");

	static const struct checkdata_value checkdata_values_bytespkts[] =
			CHECKDATA_BASE("68719476767", "68719476736");
#define CHECKS(X)                                                              \
	{ .checks = X, .size = sizeof(X) / sizeof(X[0]) }
	static const struct checkdata checkdata[] = {
			CHECKS(checkdata_values_bytes),
			CHECKS(checkdata_values_pkts),
			CHECKS(checkdata_values_bytespkts),
	};

#define TEST(config_path, mrecord, mrecord_size, checks, checks_sz)            \
	{                                                                      \
		.config_json_path = config_path, .netflow_src_ip = 0x04030201, \
		.record = mrecord, .record_size = mrecord_size,                \
		.checkdata = checks, .checkdata_size = checks_sz               \
	}

	static const struct test_params test_params[] = {
			TEST("./tests/0000-testFlowV5.json",
			     &v10Template,
			     sizeof(v10Template),
			     NULL,
			     0),
			TEST(NULL,
			     &v10Flow,
			     sizeof(v10Flow),
			     checkdata,
			     RD_ARRAYSIZE(checkdata)),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	static const const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_big_bytes),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
