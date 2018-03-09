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

#define IPFIX_TEST_HEADER                                                      \
	.unix_secs = constexpr_be32toh(1422359861),                            \
	.flow_sequence = constexpr_be32toh(33558),                             \
	.observation_id = constexpr_be32toh(2)
#define IPFIX_TEST_TEMPLATE_ID 258

#define NF9_TEST_TEMPLATE_ID IPFIX_TEST_TEMPLATE_ID
#define NF9_TEST_HEADER                                                        \
	.sys_uptime = constexpr_be32toh(12345),                                \
	.unix_secs = constexpr_be32toh(1382364130),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.source_id = constexpr_be32toh(1),

// clang-format off
#define TEST_NF9_ENTITIES(RT, R)                                               \
	RT(IN_BYTES, 4, 0, UINT32_TO_UINT8_ARR(113162))                        \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(826))                            \
	RT(PROTOCOL, 1, 0, 17)                                                 \
	RT(SRC_TOS, 1, 0, 0)                                                   \
	RT(TCP_FLAGS, 1, 0, 0)                                                 \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(2401))                       \
	RT(INPUT_SNMP, 2, 0, UINT16_TO_UINT8_ARR(0))                           \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(53))                         \
	RT(OUTPUT_SNMP, 2, 0, UINT16_TO_UINT8_ARR(0))                          \
	RT(INGRESS_VRFID, 4, 0, UINT32_TO_UINT8_ARR(0))                        \
	RT(EGRESS_VRFID, 4, 0, UINT32_TO_UINT8_ARR(16))                        \
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(27060))                    \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(0))                       \
	RT(IPV6_SRC_ADDR, 16, 0,                                               \
		0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,                \
		0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda)                \
	RT(IPV6_DST_ADDR, 16, 0,                                               \
		0x3f, 0xfe, 0x05, 0x01, 0x48, 0x19, 0x00, 0x00,                \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42)                \
	RT(IPV6_SRC_MASK, 1, 0, 0)                                             \
	RT(IPV6_DST_MASK, 1, 0, 0)                                             \
	RT(IPV6_NEXT_HOP, 16, 0,                                               \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
// clang-format on

static const NF9_TEMPLATE(v9Template,
			  NF9_TEST_HEADER,
			  NF9_TEST_TEMPLATE_ID,
			  TEST_NF9_ENTITIES);

static const NF9_FLOW(v9Flow,
		      NF9_TEST_HEADER,
		      NF9_TEST_TEMPLATE_ID,
		      TEST_NF9_ENTITIES);

#define CISCO_HTTP_EMPTY(t_type) 0x06, FLOW_APPLICATION_ID(3, 80), 0x34, t_type

#define IPFIX_ENTITIES(RT, R)                                                  \
	RT(IPV4_SRC_ADDR, 4, 0, 173, 194, 78, 189)                             \
	RT(IPV4_DST_ADDR, 4, 0, 10, 0, 30, 150)                                \
	RT(IP_PROTOCOL_VERSION, 1, 0, 4)                                       \
	RT(PROTOCOL, 1, 0, 6)                                                  \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                        \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(38946))                      \
	RT(/*TCP_DST_PORT*/ 183, 2, 0, UINT16_TO_UINT8_ARR(38946))             \
	RT(IN_SRC_MAC, 6, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)               \
	RT(IN_DST_MAC, 6, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)               \
	RT(INGRESS_VRFID, 4, 0, UINT32_TO_UINT8_ARR(0))                        \
	RT(INPUT_SNMP, 4, 0, UINT32_TO_UINT8_ARR(14))                          \
	RT(FLOW_END_REASON, 1, 0, 1)                                           \
	RT(BIFLOW_DIRECTION, 1, 0, 1)                                          \
	RT(OUT_SRC_MAC, 6, 0, 0xe0, 0x5f, 0xb9, 0x8a, 0x85, 0xd3)              \
	RT(OUT_DST_MAC, 6, 0, 0xc0, 0x3f, 0xd5, 0x69, 0x16, 0xbe)              \
	RT(OUTPUT_SNMP, 4, 0, UINT32_TO_UINT8_ARR(12))                         \
	RT(DIRECTION, 1, 0, 1)                                                 \
	RT(FLOW_SAMPLER_ID, 1, 0, 0)                                           \
	RT(EGRESS_VRFID, 4, 0, UINT32_TO_UINT8_ARR(7))                         \
	RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 1))                   \
	RT(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(0x01))                       \
	RT(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(0x02))                       \
	RT(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(0x03))                       \
	RT(CISCO_URL, 0xffff, 9, CISCO_HTTP_EMPTY(0x04))                       \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(667))                           \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(32))                             \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(363420992))               \
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(363421728))

static const IPFIX_TEMPLATE(v10Template,
			    IPFIX_TEST_HEADER,
			    IPFIX_TEST_TEMPLATE_ID,
			    IPFIX_ENTITIES);

static const IPFIX_FLOW(v10Flow,
			IPFIX_TEST_HEADER,
			IPFIX_TEST_TEMPLATE_ID,
			IPFIX_ENTITIES);

static const struct checkdata_value checkdata_values9[] = {
		{.key = "input_vrf", .value = "0"},
		{.key = "output_vrf", .value = "16"}};

static const struct checkdata_value checkdata_values10[] = {
		{.key = "input_vrf", .value = "0"},
		{.key = "output_vrf", .value = "7"}};

static int prepare_test_vrfid(void **state) {
	static const struct checkdata checkdata9 = {
			.checks = checkdata_values9,
			.size = RD_ARRAYSIZE(checkdata_values9),
	};

	static const struct checkdata checkdata10 = {
			.checks = checkdata_values10,
			.size = RD_ARRAYSIZE(checkdata_values10),
	};

#define TEST(config_path,                                                      \
	     mhost_path,                                                       \
	     mrecord,                                                          \
	     mrecord_size,                                                     \
	     checks,                                                           \
	     checks_size)                                                      \
	{                                                                      \
		.config_json_path = config_path, .host_list_path = mhost_path, \
		.netflow_src_ip = 0x04030301, .record = mrecord,               \
		.record_size = mrecord_size, .checkdata = checks,              \
		.checkdata_size = checks_size                                  \
	}

#define TEST_TEMPLATE_FLOW(config_path,                                        \
			   mhost_path,                                         \
			   template,                                           \
			   template_size,                                      \
			   flow,                                               \
			   flow_size,                                          \
			   checks,                                             \
			   checks_size)                                        \
	TEST(config_path, mhost_path, template, template_size, NULL, 0)        \
	, TEST(NULL, mhost_path, flow, flow_size, checks, checks_size)

	static const struct test_params test_params[] = {
			TEST_TEMPLATE_FLOW(
					"./tests/0024-testEnrichmentV10.json",
					"./tests/0011-data/",
					&v9Template,
					sizeof(v9Template),
					&v9Flow,
					sizeof(v9Flow),
					&checkdata9,
					1),
			TEST_TEMPLATE_FLOW(NULL,
					   NULL,
					   &v10Template,
					   sizeof(v10Template),
					   &v10Flow,
					   sizeof(v10Flow),
					   &checkdata10,
					   1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow, prepare_test_vrfid),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
