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

#define FLOW_TEMPLATE_ID 269
#define FLOW_HEADER                                                            \
	.unix_secs = constexpr_be32toh(1382637021),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.observation_id = constexpr_be32toh(1),

// clang-format off
#define IPFIX_ENTITIES_BASE(X)                                                 \
	X(IP_PROTOCOL_VERSION, 1, 0, 4)                                        \
	X(PROTOCOL, 1, 0, 6)                                                   \
	X(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713))                       \
	X(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                         \
	X(FLOW_END_REASON, 1, 0, 3)                                            \
	X(BIFLOW_DIRECTION, 1, 0, 1)                                           \
	X(FLOW_SAMPLER_ID, 1, 0, 0)                                            \
	X(TRANSACTION_ID, 8, 0,                                                \
	  0x8f, 0x63, 0xf3, 0x40, 0x00, 0x01, 0x00, 0x00)                      \
	X(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                  \
	X(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x01)      \
	X(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x02)      \
	X(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x03)      \
	X(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x04)      \
	X(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(2744))                           \
	X(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(31))                              \
	X(FIRST_SWITCHED , 4, 0, 0x0f, 0xed, 0x0a, 0xc0)                       \
	X(LAST_SWITCHED, 4, 0, 0x0f, 0xee, 0x18, 0x00)
// clang-format on

#define IPFIX_ENTITIES(RT, R)                                                  \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44)                               \
	RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                              \
	IPFIX_ENTITIES_BASE(RT)

// clang-format off
#define IPFIX_ENTITIES_V6(RT, R)                                               \
	RT(IPV6_SRC_ADDR, 16, 0,                                               \
	   0x20, 0x01, 0x04, 0x28, 0xce, 0x00, 0x20, 0x11,                     \
	   0x0d, 0x5a, 0x60, 0x69, 0x24, 0x67, 0x9b, 0xd1)                     \
	RT(IPV6_DST_ADDR, 16, 0,                                               \
	   0x20, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,                     \
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)                     \
	IPFIX_ENTITIES_BASE(RT)                                                \
	R(IPV6_SRC_ADDR, 16, 0,                                                \
	  0x20, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,                      \
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)                      \
	R(IPV6_DST_ADDR, 16, 0,                                                \
	  0x20, 0x01, 0x04, 0x28, 0xce, 0x00, 0x20, 0x11,                      \
	  0x0d, 0x5a, 0x60, 0x69, 0x24, 0x67, 0x9b, 0xd1)                      \
	IPFIX_ENTITIES_BASE(R)
// clang-format on

static const IPFIX_TEMPLATE(v10Template,
			    FLOW_HEADER,
			    FLOW_TEMPLATE_ID,
			    IPFIX_ENTITIES);

static const IPFIX_FLOW(v10Flow, FLOW_HEADER, FLOW_TEMPLATE_ID, IPFIX_ENTITIES);

static const IPFIX_TEMPLATE(v10Template_v6,
			    FLOW_HEADER,
			    FLOW_TEMPLATE_ID,
			    IPFIX_ENTITIES_V6);

static const IPFIX_FLOW(v10Flow_v6,
			FLOW_HEADER,
			FLOW_TEMPLATE_ID,
			IPFIX_ENTITIES_V6);

#define CHECKDATA(left_name,                                                   \
		  left_ip,                                                     \
		  left_net,                                                    \
		  left_net_name,                                               \
		  right_name,                                                  \
		  right_ip,                                                    \
		  right_net,                                                   \
		  right_net_name,                                              \
		  direction)                                                   \
	{                                                                      \
		{.key = left_name, .value = left_ip},                          \
				{.key = left_name "_net", .value = left_net},  \
				{.key = left_name "_net_name",                 \
				 .value = left_net_name},                      \
				{.key = right_name, .value = right_ip},        \
				{.key = right_name "_net",                     \
				 .value = right_net},                          \
				{.key = right_name "_net_name",                \
				 .value = right_net_name},                     \
				{.key = "direction", .value = direction},      \
	}

static int prepare_test_nf10_home_nets0(void **state,
					const struct checkdata *checkdata_v4,
					const size_t checkdata_v4_size,
					const struct checkdata *checkdata_v6,
					const size_t checkdata_v6_size,
					const bool normalize_directions) {
#define TEST(nf_dev_ip, mrecord, mrecord_size, checks, checks_sz, ...)         \
	{                                                                      \
		.netflow_src_ip = nf_dev_ip, .record = mrecord,                \
		.record_size = mrecord_size, .checkdata = checks,              \
		.checkdata_size = checks_sz, __VA_ARGS__                       \
	}

#define TEST_TEMPLATE_FLOW0(nf_dev_ip,                                         \
			    template,                                          \
			    template_size,                                     \
			    flow,                                              \
			    flow_size,                                         \
			    checks,                                            \
			    checks_sz,                                         \
			    ...)                                               \
	TEST(nf_dev_ip, template, template_size, NULL, 0, __VA_ARGS__)         \
	, TEST(nf_dev_ip, flow, flow_size, checks, checks_sz, )

#define TEST_TEMPLATE_FLOW_V4(nf_dev_ip, ...)                                  \
	TEST_TEMPLATE_FLOW0(nf_dev_ip,                                         \
			    &v10Template,                                      \
			    sizeof(v10Template),                               \
			    &v10Flow,                                          \
			    sizeof(v10Flow),                                   \
			    checkdata_v4,                                      \
			    checkdata_v4_size,                                 \
			    __VA_ARGS__)

#define TEST_TEMPLATE_FLOW_V6(nf_dev_ip, ...)                                  \
	TEST_TEMPLATE_FLOW0(nf_dev_ip,                                         \
			    &v10Template_v6,                                   \
			    sizeof(v10Template_v6),                            \
			    &v10Flow_v6,                                       \
			    sizeof(v10Flow_v6),                                \
			    checkdata_v6,                                      \
			    checkdata_v6_size,                                 \
			    __VA_ARGS__)

	// clang-format off
	// different span port configuration should not affect when no mac is
	// implied
	const struct test_params test_params[] = {
		TEST_TEMPLATE_FLOW_V4(
			0x04030201,
			.config_json_path = "./tests/0022-testHomeNetsV10.json",
			.host_list_path = "./tests/0011-data/",
			.normalize_directions = normalize_directions),

		TEST_TEMPLATE_FLOW_V4(0x04030301, ),
		TEST_TEMPLATE_FLOW_V4(0x04030401, ),
		TEST_TEMPLATE_FLOW_V6(0x04030201, ),
		TEST_TEMPLATE_FLOW_V6(0x04030301, ),
		TEST_TEMPLATE_FLOW_V6(0x04030401, ),
	};
	// clang-format on

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

static int prepare_test_nf10_home_nets_normalize(void **state) {
#define CHECKS(t_checks)                                                       \
	{ .size = RD_ARRAYSIZE(t_checks), .checks = t_checks }
	static const struct checkdata_value checkdata_values1[] =
			CHECKDATA("lan_ip",
				  "10.13.122.44",
				  "10.13.30.0/16",
				  "users",
				  "wan_ip",
				  "66.220.152.19",
				  NULL,
				  NULL,
				  "upstream");

	static const struct checkdata_value checkdata_values_v6_1[] =
			CHECKDATA("lan_ip",
				  "2001:0428:ce00:2011:0d5a:6069:2467:9bd1",
				  "2001:0428:ce00:0000:0000:0000:0000:0000/48",
				  "users6",
				  "wan_ip",
				  "2001:0008:0000:0000:0000:0000:0000:0001",
				  NULL,
				  NULL,
				  "upstream");

	static const struct checkdata_value checkdata_values_v6_2[] =
			CHECKDATA("wan_ip",
				  "2001:0008:0000:0000:0000:0000:0000:0001",
				  NULL,
				  NULL,
				  "lan_ip",
				  "2001:0428:ce00:2011:0d5a:6069:2467:9bd1",
				  "2001:0428:ce00:0000:0000:0000:0000:0000/48",
				  "users6",
				  "downstream");

	static const struct checkdata checkdata_v4[] = {
			CHECKS(checkdata_values1),
	};
	static const struct checkdata checkdata_v6[] = {
			CHECKS(checkdata_values_v6_1),
			CHECKS(checkdata_values_v6_2),
	};

	static const bool normalize_directions = true;
	return prepare_test_nf10_home_nets0(state,
					    checkdata_v4,
					    RD_ARRAYSIZE(checkdata_v4),
					    checkdata_v6,
					    RD_ARRAYSIZE(checkdata_v6),
					    normalize_directions);
}

static int prepare_test_nf10_home_nets_dont_normalize(void **state) {
#define CHECKS(t_checks)                                                       \
	{ .size = RD_ARRAYSIZE(t_checks), .checks = t_checks }
	static const struct checkdata_value checkdata_values1[] =
			CHECKDATA("src",
				  "10.13.122.44",
				  "10.13.30.0/16",
				  "users",
				  "dst",
				  "66.220.152.19",
				  NULL,
				  NULL,
				  NULL);

	static const struct checkdata_value checkdata_values_v6_1[] =
			CHECKDATA("src",
				  "2001:0428:ce00:2011:0d5a:6069:2467:9bd1",
				  "2001:0428:ce00:0000:0000:0000:0000:0000/48",
				  "users6",
				  "dst",
				  "2001:0008:0000:0000:0000:0000:0000:0001",
				  NULL,
				  NULL,
				  NULL);

	static const struct checkdata_value checkdata_values_v6_2[] =
			CHECKDATA("src",
				  "2001:0008:0000:0000:0000:0000:0000:0001",
				  NULL,
				  NULL,
				  "dst",
				  "2001:0428:ce00:2011:0d5a:6069:2467:9bd1",
				  "2001:0428:ce00:0000:0000:0000:0000:0000/48",
				  "users6",
				  NULL);

	static const struct checkdata checkdata_v4[] = {
			CHECKS(checkdata_values1),
	};
	static const struct checkdata checkdata_v6[] = {
			CHECKS(checkdata_values_v6_1),
			CHECKS(checkdata_values_v6_2),
	};

	static const bool normalize_directions = false;
	return prepare_test_nf10_home_nets0(state,
					    checkdata_v4,
					    RD_ARRAYSIZE(checkdata_v4),
					    checkdata_v6,
					    RD_ARRAYSIZE(checkdata_v6),
					    normalize_directions);
}

int main() {
	// clang-format off
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(testFlow,
				prepare_test_nf10_home_nets_dont_normalize),
		cmocka_unit_test_setup(testFlow,
				prepare_test_nf10_home_nets_normalize),
	};
	// clang-format on

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
