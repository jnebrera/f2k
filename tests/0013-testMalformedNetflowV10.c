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

#define IPFIX_HEADER                                                           \
	.unix_secs = constexpr_be32toh(1382637021),                            \
	.flow_sequence = constexpr_be32toh(1080), .observation_id = 1

// Valid
#define IPFIX_ENTITIES(RT, R)                                                  \
	RT(FLOW_START_SEC, 4, 0, UINT32_TO_UINT8_ARR(1000))                    \
	RT(FLOW_END_SEC, 4, 0, UINT32_TO_UINT8_ARR(1000))                      \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44)                               \
	RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                              \
	RT(IP_PROTOCOL_VERSION, 1, 0, 0x04)                                    \
	RT(PROTOCOL, 1, 0, 0x06)                                               \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713))                      \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                        \
	RT(FLOW_END_REASON, 1, 0, 3)                                           \
	RT(BIFLOW_DIRECTION, 1, 0, 1)                                          \
	RT(FLOW_SAMPLER_ID, 1, 0, 0)                                           \
	RT(TRANSACTION_ID, 8, 0, UINT64_TO_UINT8_ARR(1))                       \
	RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                 \
	RT(IN_BYTES, 0x08, 0, UINT64_TO_UINT8_ARR(47114))                      \
	RT(IN_PKTS, 0x04, 0, UINT32_TO_UINT8_ARR(31))                          \
	RT(FIRST_SWITCHED, 0x04, 0, 0x0f, 0xed, 0x0a, 0xc0)                    \
	RT(LAST_SWITCHED, 0x04, 0, 0x0f, 0xee, 0x18, 0x00)

#define TEST_TEMPLATE_ID 269

static const IPFIX_TEMPLATE(v10Template,
			    IPFIX_HEADER,
			    TEST_TEMPLATE_ID,
			    IPFIX_ENTITIES);
static const IPFIX_FLOW(v10Flow,
			IPFIX_HEADER,
			TEST_TEMPLATE_ID,
			IPFIX_ENTITIES);

static int prepare_test_nf10_malformed(void **state) {
#define TEST(config_path, mhosts_db_path, mrecord, mrecord_size)               \
	{                                                                      \
		.config_json_path = config_path,                               \
		.host_list_path = mhosts_db_path,                              \
		.netflow_src_ip = 0x04030201, .record = mrecord,               \
		.record_size = mrecord_size, .checkdata = NULL,                \
		.checkdata_size = 0                                            \
	}

	// clang-format off
	static const struct test_params test_params[] = {
		[0] = TEST("./tests/0000-testFlowV5.json",
			   "./tests/0011-data/",
			   &v10Template, sizeof(v10Template)),

		// Producing malformation with -10
		[1] = TEST(NULL, NULL, &v10Flow, sizeof(v10Flow) - 10),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_nf10_malformed),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
