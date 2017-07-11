/*
  Copyright (C) 2015-2017 Eneo Tecnologia S.L.
  Copyright (C) 2017 Eugenio Pérez.
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

#define TEST_TEMPLATE_ID 259
#define TEST_IPFIX_HEADER                                                      \
	.unix_secs = constexpr_be32toh(1382637021),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.observation_id = constexpr_be32toh(0x00010000)

#define CISCO_ENTITY_EMPTY(port, id) 0x06, 0x03, 0x00, 0x00, port, 0x34, id

#define TEST_ENTITIES0(X)                                                      \
	X(IPV4_SRC_ADDR, 4, 0, 1, 2, 3, 4)                                     \
	X(IPV4_DST_ADDR, 4, 0, 10, 11, 12, 13)                                 \
	X(IP_PROTOCOL_VERSION, 1, 0, 4)                                        \
	X(PROTOCOL, 1, 0, 6)                                                   \
	X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713))                       \
	X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                         \
	X(IN_SRC_MAC, 6, 0, 0x00, 0x11, 0x44, 0x55, 0xbb, 0xdd)                \
	X(FLOW_END_REASON, 1, 0, 3)                                            \
	X(BIFLOW_DIRECTION, 1, 0, 1)                                           \
	X(TRANSACTION_ID, 8, 0, UINT64_TO_UINT8_ARR(1100601320335))            \
	X(IN_DST_MAC, 6, 0, 0x00, 0xdf, 0x5f, 0x4e, 0x5d, 0x1e)                \
	X(OUT_DST_MAC, 6, 0, 0x00, 0x4e, 0xa3, 0x3c, 0x3d, 0x5e)               \
	X(DIRECTION, 1, 0, 1)                                                  \
	X(FLOW_SAMPLER_ID, 1, 0, 0)                                            \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                  \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(25, 1))                     \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(25, 2))                     \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(80, 1))                     \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(80, 2))                     \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(80, 3))                     \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(80, 4))                     \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(110, 1))                    \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(196, 1))                    \
	X(CISCO_URL, 0xffff, 9, CISCO_ENTITY_EMPTY(196, 2))                    \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(2744))                           \
	X(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(31))                              \
	X(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267193024))                \
	X(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267261952))

#define TEST_ENTITIES(RT, R)                                                   \
	TEST_ENTITIES0(RT)                                                     \
	TEST_ENTITIES0(R)                                                      \
	TEST_ENTITIES0(R)                                                      \
	TEST_ENTITIES0(R)                                                      \
	TEST_ENTITIES0(R)                                                      \
	TEST_ENTITIES0(R)                                                      \
	TEST_ENTITIES0(R)                                                      \
	TEST_ENTITIES0(R)

static const IPFIX_TEMPLATE(v10Template,
			    TEST_IPFIX_HEADER,
			    TEST_TEMPLATE_ID,
			    TEST_ENTITIES);
static const IPFIX_FLOW(v10Flow,
			TEST_IPFIX_HEADER,
			TEST_TEMPLATE_ID,
			TEST_ENTITIES);

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
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1082);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1083);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1084);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1085);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1086);
DECL_CHECKDATA_VALUE_FLOW_SEQUENCE(1087);

static const struct checkdata checkdata_v10_flow_seq[] = {
		CHECKDATA_VALUE_ENTRY(1080),
		CHECKDATA_VALUE_ENTRY(1081),
		CHECKDATA_VALUE_ENTRY(1082),
		CHECKDATA_VALUE_ENTRY(1083),
		CHECKDATA_VALUE_ENTRY(1084),
		CHECKDATA_VALUE_ENTRY(1085),
		CHECKDATA_VALUE_ENTRY(1086),
		CHECKDATA_VALUE_ENTRY(1087),
};

static int prepare_test_nf10_flow_seq(void **state) {
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
			&v10Template,
			sizeof(v10Template),
			&v10Flow,
			sizeof(v10Flow),
			checkdata_v10_flow_seq,
			RD_ARRAYSIZE(checkdata_v10_flow_seq))};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_nf10_flow_seq),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
