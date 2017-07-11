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

#define TEST_TEMPLATE_ID 257
#define TEST_FLOW_HEADER                                                       \
	.sys_uptime = constexpr_be32toh(12345),                                \
	.unix_secs = constexpr_be32toh(1382364130),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.source_id = constexpr_be32toh(1)

// clang-format off
#define TEST_NF9_ENTITIES(RT, R) \
	RT(IN_BYTES, 4, 0, UINT32_TO_UINT8_ARR(113162))                        \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(826))                            \
	RT(IP_PROTOCOL_VERSION, 1, 0, 17)                                      \
	RT(IP_TOS, 1, 0, 0)                                                    \
   	RT(TCP_FLAGS, 1, 0, 0)                                                 \
   	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(2401))                       \
   	RT(INPUT_SNMP, 2, 0, 0)                                                \
   	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(53))                         \
   	RT(OUTPUT_SNMP, 2, 0, 0)                                               \
	RT(SRC_AS, 4, 0, UINT32_TO_UINT8_ARR(0))                               \
	RT(DST_AS, 4, 0, UINT32_TO_UINT8_ARR(0))                               \
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(27060))                    \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(0))                       \
	RT(IPV6_SRC_ADDR, 16, 0,                                               \
		0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,                \
		0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda)                \
	RT(IPV6_DST_ADDR, 16, 0,                                               \
		0x3f, 0xfe, 0x05, 0x01, 0x48, 0x19, 0x00, 0x00,                \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42)                \
	RT(IPV6_SRC_MASK, 1, 0, 0x00)                                          \
	RT(IPV6_DST_MASK, 1, 0, 0x00)                                          \
	RT(IPV6_NEXT_HOP, 16, 0,                                               \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

// clang-format on

static const NF9_TEMPLATE(v9Template,
			  TEST_FLOW_HEADER,
			  TEST_TEMPLATE_ID,
			  TEST_NF9_ENTITIES);

static const NF9_FLOW(v9Flow,
		      TEST_FLOW_HEADER,
		      TEST_TEMPLATE_ID,
		      TEST_NF9_ENTITIES);

static int prepare_test_nf9_enrichment(void **state) {
	static const struct checkdata_value checkdata_values1 = {
			.key = "testing", .value = "abc"};
	static const struct checkdata checkdata = {
			.checks = &checkdata_values1, .size = 1,
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

	const struct test_params test_params[] = {
			TEST_TEMPLATE_FLOW(
					"./tests/0024-testEnrichmentV10.json",
					"./tests/0011-data/",
					&v9Template,
					sizeof(v9Template),
					&v9Flow,
					sizeof(v9Flow),
					&checkdata,
					1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_nf9_enrichment),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
