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

#define TEMPLATE_ID 258
#define V9_HEADER                                                              \
	.sys_uptime = constexpr_be32toh(12345),                                \
	.unix_secs = constexpr_be32toh(1478780782),                            \
	.flow_sequence = 0x38040000, .source_id = 0x01000000

#define V9_ENTITIES(RT, R)                                                     \
	RT(IN_BYTES, 4, 0, UINT32_TO_UINT8_ARR(113162))                        \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(826))                            \
	RT(PROTOCOL, 1, 0, 17)                                                 \
	RT(SRC_TOS, 1, 0, 0)                                                   \
	RT(TCP_FLAGS, 1, 0, 0)                                                 \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(2401))                       \
	RT(INPUT_SNMP, 2, 0, 0, 0)                                             \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(53))                         \
	RT(OUTPUT_SNMP, 2, 0, 0, 0)                                            \
	RT(SRC_AS, 4, 0, 0, 0, 0, 0)                                           \
	RT(DST_AS, 4, 0, 0, 0, 0, 0)                                           \
	RT(LAST_SWITCHED, 4, 0, 0, 0, 0, 0)                                    \
	RT(FIRST_SWITCHED, 4, 0, 0, 0, 0, 0)                                   \
	RT(IPV6_SRC_ADDR,                                                      \
	   16,                                                                 \
	   0,                                                                  \
	   0x3f,                                                               \
	   0xfe,                                                               \
	   0x05,                                                               \
	   0x07,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x01,                                                               \
	   0x02,                                                               \
	   0x00,                                                               \
	   0x86,                                                               \
	   0xff,                                                               \
	   0xfe,                                                               \
	   0x05,                                                               \
	   0x80,                                                               \
	   0xda)                                                               \
	RT(IPV6_DST_ADDR,                                                      \
	   16,                                                                 \
	   0,                                                                  \
	   0x3f,                                                               \
	   0xfe,                                                               \
	   0x05,                                                               \
	   0x01,                                                               \
	   0x48,                                                               \
	   0x19,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x42)                                                               \
	RT(IPV6_SRC_MASK, 1, 0, 0x00)                                          \
	RT(IPV6_DST_MASK, 1, 0, 0x00)                                          \
	RT(IPV6_NEXT_HOP,                                                      \
	   16,                                                                 \
	   0,                                                                  \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00,                                                               \
	   0x00)

static const struct checkdata_value checkdata_values1[] = {
		{.key = "type", .value = "netflowv9"},
		{.key = "l4_proto", .value = "17"},
		{.key = "tos", .value = "0"},
		{.key = "tcp_flags", .value = NULL},
		{.key = "src_port", .value = "2401"},
		{.key = "input_snmp", .value = "0"},
		{.key = "dst_port", .value = "53"},
		{.key = "output_snmp", .value = "0"},
		{.key = "prev_as", .value = "0"},
		{.key = "next_as", .value = "0"},
		{.key = "src",
		 .value = "3ffe:0507:0000:0001:0200:86ff:fe05:80da"},
		{.key = "dst",
		 .value = "3ffe:0501:4819:0000:0000:0000:0000:0042"},
		{.key = "sensor_ip", .value = "4.3.2.1"},
		{.key = "sensor_name", .value = "FlowTest"},
		{.key = "first_switched", .value = "1478780782"},
		{.key = "timestamp", .value = "1478780782"},
		{.key = "bytes", .value = "113162"},
		{.key = "pkts", .value = "826"},
};

static int prepare_test_nf9_ipv6(void **state) {
	static const NF9_TEMPLATE(
			v9Template, V9_HEADER, TEMPLATE_ID, V9_ENTITIES);
	static const NF9_FLOW(v9Flow, V9_HEADER, TEMPLATE_ID, V9_ENTITIES);

	static const struct checkdata sl1_checkdata = {
			.checks = checkdata_values1,
			.size = RD_ARRAYSIZE(checkdata_values1),
	};

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

	// clang-format off
	static const struct test_params test_params[] = {
		TEST("./tests/0000-testFlowV5.json",
		     "./tests/0011-data/",
		     &v9Template,
		     sizeof(v9Template),
		     NULL,
		     0),

		TEST(NULL,
		     NULL,
		     &v9Flow,
		     sizeof(v9Flow),
		     &sl1_checkdata,
		     1),
	};
	// clang-format on

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow, prepare_test_nf9_ipv6),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
