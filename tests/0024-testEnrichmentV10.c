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

#define FLOW_TEMPLATE_ID 256
#define FLOW_HEADER                                                            \
	.unix_secs = constexpr_be32toh(1382637021),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.observation_id = constexpr_be32toh(1),

#define IPFIX_ENTITIES(RT, R)                                                  \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44)                               \
	RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                              \
	RT(IP_PROTOCOL_VERSION, 1, 0, 4)                                       \
	RT(PROTOCOL, 1, 0, 6)                                                  \
	RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713))                      \
	RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                        \
	RT(FLOW_END_REASON, 1, 0, 3)                                           \
	RT(BIFLOW_DIRECTION, 1, 0, 1)                                          \
	RT(FLOW_SAMPLER_ID, 1, 0, 0)                                           \
	RT(TRANSACTION_ID, 8, 0, UINT64_TO_UINT8_ARR(1100601320335))           \
	RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                 \
	RT(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x01)     \
	RT(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x02)     \
	RT(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x03)     \
	RT(CISCO_URL, 0xffff, 9, 0x06, 0x03, 0x00, 0x00, 0x50, 0x34, 0x04)     \
	RT(IN_BYTES, 8, 0, UINT32_TO_UINT8_ARR(2744))                          \
	RT(IN_PKTS, 4, 0, UINT64_TO_UINT8_ARR(31))                             \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267261952))               \
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267193024))

static const IPFIX_TEMPLATE(v10Template,
			    FLOW_HEADER,
			    FLOW_TEMPLATE_ID,
			    IPFIX_ENTITIES);

static const IPFIX_FLOW(v10Flow, FLOW_HEADER, FLOW_TEMPLATE_ID, IPFIX_ENTITIES);

static int prepare_test_nf10_enrichment(void **state) {
	static const struct checkdata_value checkdata_values1 = {
			.key = "testing", .value = "abc"};

	static const struct checkdata checkdata = {.checks = &checkdata_values1,
						   .size = 1};

#define TEST(config_path,                                                      \
	     mhost_path,                                                       \
	     mrecord,                                                          \
	     mrecord_size,                                                     \
	     checks,                                                           \
	     checks_sz)                                                        \
	{                                                                      \
		.config_json_path = config_path, .host_list_path = mhost_path, \
		.netflow_src_ip = 0x04030301, .record = mrecord,               \
		.record_size = mrecord_size, .checkdata = checks,              \
		.checkdata_size = checks_sz                                    \
	}

#define TEST_TEMPLATE_FLOW(config_path,                                        \
			   mhost_path,                                         \
			   template,                                           \
			   template_size,                                      \
			   flow,                                               \
			   flow_size,                                          \
			   checks,                                             \
			   checks_sz)                                          \
	TEST(config_path, mhost_path, template, template_size, NULL, 0)        \
	, TEST(NULL, mhost_path, flow, flow_size, checks, checks_sz)

	static const struct test_params test_params[] = {
			TEST_TEMPLATE_FLOW(
					"./tests/0024-testEnrichmentV10.json",
					"./tests/0011-data/",
					&v10Template,
					sizeof(v10Template),
					&v10Flow,
					sizeof(v10Flow),
					&checkdata,
					1),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_nf10_enrichment),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
