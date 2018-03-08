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

// netflow v9 observed on PaloAlto (c) v7.1.0 virtual firewall
// Observed particularities:
//  - Instead of exporting one flowset with many flows, they will export many
//    flowsets with 1 flow in each flowset.
// This also test multiple flowset in the same UDP packet, that only where
// tested in the case Template+flow(s)

#define TEST_FLOW_HEADER                                                       \
	.sys_uptime = constexpr_be32toh(5592000),                              \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.source_id = constexpr_be32toh(1),

#define TEST_TEMPLATE_ID 256

#define TEST_FIREWALL_BASE(RT, R, t_icmp_type, t_flow_id)                      \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(98))                            \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(1))                              \
	RT(PROTOCOL, 1, 0, 1)                                                  \
	RT(SRC_TOS, 1, 0, 0)                                                   \
	RT(TCP_FLAGS, 1, 0, 0x00)                                              \
	RT(L4_SRC_PORT, 2, 0, 0x00, 0x00)                                      \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 94, 223)                               \
	RT(INPUT_SNMP, 4, 0, 0x00, 0x00, 0x00, 0x00)                           \
	RT(L4_DST_PORT, 2, 0, 0x00, 0x00)                                      \
	RT(IPV4_DST_ADDR, 4, 0, 10, 13, 94, 223)                               \
	RT(OUTPUT_SNMP, 4, 0, 0x00, 0x00, 0x00, 0x04)                          \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000))                  \
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000))                   \
	RT(ICMP_TYPE, 2, 0, UINT16_TO_UINT8_ARR(t_icmp_type))                  \
	RT(DIRECTION, 1, 0, 0)                                                 \
	RT(FLOW_ID, 8, 0, UINT64_TO_UINT8_ARR(t_flow_id))                      \
	RT(233 /* FIREWALL_EVENT */, 1, 0, 0)

#define TEST_ICMP_TYPE_ENTITIES_1(RT, R) TEST_FIREWALL_BASE(RT, R, 0, 599)
#define TEST_ICMP_TYPE_ENTITIES_2(RT, R) TEST_FIREWALL_BASE(RT, R, 265, 599)

#define FIREWALL_CHECKDATA(t_icmp_type, t_flow_id)                             \
	{                                                                      \
			{.key = "type", .value = "netflowv9"},                 \
			{.key = "icmp_type", .value = #t_icmp_type},           \
			{.key = "flow_id", .value = #t_flow_id},               \
	};

static int prepare_test_firewall_base(const void *v9_flow,
				      size_t v9_flow_size,
				      const struct checkdata *checkdata,
				      size_t checkdata_size,
				      void **state) {
	// Same template for all tests
	static const NF9_TEMPLATE(v9Template,
				  TEST_FLOW_HEADER,
				  TEST_TEMPLATE_ID,
				  TEST_ICMP_TYPE_ENTITIES_1);

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
	const struct test_params test_params[] = {
		TEST("./tests/0000-testFlowV5.json",
		     "./tests/0009-data/",
		     &v9Template,
		     sizeof(v9Template),
		     NULL,
		     0),

		TEST(NULL,
		     NULL,
		     v9_flow,
		     v9_flow_size,
		     checkdata,
		     checkdata_size),
	};
	// clang-format on

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

// Flowset with only one flow
// clang-format off
#define ONE_FLOW_FLOWSET(t_template_id, t_entities) {                          \
	.flow_set_header = {                                                   \
		.templateFlowset = constexpr_be16toh(t_template_id),           \
		.flowsetLen = constexpr_be16toh(sizeof(V9TemplateHeader) +     \
			                        FLOW_BYTES_LENGTH(t_entities)) \
	},                                                                     \
	.buffer = {t_entities(FLOW_BYTES, FLOW_BYTES)}                         \
}
// clang-format on

// Two flows, each one in it's own flowset
// Note that entities1 and entities2 MUST be the same length, i.e., to have the
// same template
#define FIREWALL_TWO_FLOWS(t_var,                                              \
			   t_flow_header,                                      \
			   t_template_id,                                      \
			   t_entities_1,                                       \
			   t_entities_2)                                       \
	struct {                                                               \
		V9FlowHeader flow_header;                                      \
		struct {                                                       \
			V9TemplateHeader flow_set_header;                      \
			uint8_t buffer[FLOW_BYTES_LENGTH(t_entities_1)];       \
		} __attribute__((packed)) flowset[2];                          \
		/* clang-format off */                                         \
	} __attribute__((packed)) t_var = {                                    \
		.flow_header = {                                               \
			.version = constexpr_be16toh(9),                       \
			.unix_secs = constexpr_be32toh(1520362144),            \
			.count = constexpr_be16toh(2),                         \
			t_flow_header                                          \
		},                                                             \
		.flowset = {                                                   \
			ONE_FLOW_FLOWSET(t_template_id, t_entities_1),         \
			ONE_FLOW_FLOWSET(t_template_id, t_entities_2),         \
		}                                                              \
	}
// clang-format on

static int prepare_test_firewall_icmp_type(void **state) {
	static const FIREWALL_TWO_FLOWS(it_flow,
					TEST_FLOW_HEADER,
					TEST_TEMPLATE_ID,
					TEST_ICMP_TYPE_ENTITIES_1,
					TEST_ICMP_TYPE_ENTITIES_2);

	static const struct checkdata_value checkdata1[] =
			FIREWALL_CHECKDATA(0, 599);

	static const struct checkdata_value checkdata2[] =
			FIREWALL_CHECKDATA(265, 599);

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
	};

	return prepare_test_firewall_base(&it_flow,
					  sizeof(it_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

#define TEST_FLOW_ID_ENTITIES_1(RT, R) TEST_FIREWALL_BASE(RT, R, 0, 0)
#define TEST_FLOW_ID_ENTITIES_2(RT, R) TEST_FIREWALL_BASE(RT, R, 0, 599)
static int prepare_test_firewall_flow_id(void **state) {
	static const FIREWALL_TWO_FLOWS(it_flow,
					TEST_FLOW_HEADER,
					TEST_TEMPLATE_ID,
					TEST_FLOW_ID_ENTITIES_1,
					TEST_FLOW_ID_ENTITIES_2);

	static const struct checkdata_value checkdata1[] =
			FIREWALL_CHECKDATA(0, 0);

	static const struct checkdata_value checkdata2[] =
			FIREWALL_CHECKDATA(0, 599);

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
	};

	return prepare_test_firewall_base(&it_flow,
					  sizeof(it_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_firewall_icmp_type),
			cmocka_unit_test_setup(testFlow,
					       prepare_test_firewall_flow_id),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
