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
// firewall export 4 types of templates:
// No nat information - ipv4 and ipv6
// with NAT information - ipv4 and ipv6
// Testing also forwarding status ipfix entity

#define TEST_FLOW_HEADER                                                       \
	.sys_uptime = constexpr_be32toh(5592000),                              \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.source_id = constexpr_be32toh(1),

#define TEST_IPFIX_FLOW_HEADER                                                 \
	.unix_secs = constexpr_be32toh(1382364130),                            \
	.flow_sequence = constexpr_be32toh(1080),                              \
	.observation_id = constexpr_be32toh(256),

#define TEST_NF9_TEMPLATE_ID 256
#define TEST_IPFIX_FIXEDLEN_TEMPLATE_ID (TEST_NF9_TEMPLATE_ID + 1)
#define TEST_IPFIX_VARLEN_TEMPLATE_ID (TEST_NF9_TEMPLATE_ID + 2)

#define TEST_NF9_BASE(RT, R)                                                   \
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
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000))

#define TEST_NF9_PRIVATE_FIXLEN(RT, R)                                         \
	TEST_NF9_BASE(RT, R)                                                   \
	RT(NF9_PRIVATE_65, 1, 0, 0x98)                                         \
	RT(NF9_PRIVATE_66, 3, 0, 0x44, 0x65, 0x96)                             \
	RT(NF9_PRIVATE_67, 5, 0, 0xc0, 0x2c, 0x5e, 0x8f, 0x0a)                 \
	RT(NF9_PRIVATE_68,                                                     \
	   20,                                                                 \
	   0,                                                                  \
	   0x62,                                                               \
	   0xb3,                                                               \
	   0x93,                                                               \
	   0x8e,                                                               \
	   0x86,                                                               \
	   0x0d,                                                               \
	   0x4f,                                                               \
	   0x7c,                                                               \
	   0x44,                                                               \
	   0x88,                                                               \
	   0x34,                                                               \
	   0xce,                                                               \
	   0x96,                                                               \
	   0xb3,                                                               \
	   0xca,                                                               \
	   0x83,                                                               \
	   0x2d,                                                               \
	   0x85,                                                               \
	   0xef,                                                               \
	   0x54)                                                               \
	RT(NF9_PRIVATE_69,                                                     \
	   15,                                                                 \
	   0,                                                                  \
	   0x48,                                                               \
	   0xe9,                                                               \
	   0x65,                                                               \
	   0xd9,                                                               \
	   0x89,                                                               \
	   0xa7,                                                               \
	   0xe3,                                                               \
	   0x40,                                                               \
	   0x24,                                                               \
	   0x5c,                                                               \
	   0x48,                                                               \
	   0x02,                                                               \
	   0x71,                                                               \
	   0xca,                                                               \
	   0xa1)

// 2-byte encoded length
#define TEST_NF9_PRIVATE_VARLEN(RT, R)                                         \
	TEST_NF9_BASE(RT, R)                                                   \
	RT(NF9_PRIVATE_65, 1, 0, 0x98)                                         \
	RT(NF9_PRIVATE_66, 3, 0, 0x44, 0x65, 0x96)                             \
	RT(NF9_PRIVATE_67, 5, 0, 0xc0, 0x2c, 0x5e, 0x8f, 0x0a)                 \
	RT(NF9_PRIVATE_68,                                                     \
	   0xffff,                                                             \
	   0,                                                                  \
	   20,                                                                 \
	   0x62,                                                               \
	   0xb3,                                                               \
	   0x93,                                                               \
	   0x8e,                                                               \
	   0x86,                                                               \
	   0x0d,                                                               \
	   0x4f,                                                               \
	   0x7c,                                                               \
	   0x44,                                                               \
	   0x88,                                                               \
	   0x34,                                                               \
	   0xce,                                                               \
	   0x96,                                                               \
	   0xb3,                                                               \
	   0xca,                                                               \
	   0x83,                                                               \
	   0x2d,                                                               \
	   0x85,                                                               \
	   0xef,                                                               \
	   0x54)                                                               \
	RT(NF9_PRIVATE_69,                                                     \
	   0xffff,                                                             \
	   0,                                                                  \
	   0xff,                                                               \
	   0x00,                                                               \
	   15,                                                                 \
	   0x48,                                                               \
	   0xe9,                                                               \
	   0x65,                                                               \
	   0xd9,                                                               \
	   0x89,                                                               \
	   0xa7,                                                               \
	   0xe3,                                                               \
	   0x40,                                                               \
	   0x24,                                                               \
	   0x5c,                                                               \
	   0x48,                                                               \
	   0x02,                                                               \
	   0x71,                                                               \
	   0xca,                                                               \
	   0xa1)

// Basic flow template
static const NF9_TEMPLATE(nf9_private_template,
			  TEST_FLOW_HEADER,
			  TEST_NF9_TEMPLATE_ID,
			  TEST_NF9_PRIVATE_FIXLEN);

static const NF9_FLOW(nf9_private,
		      TEST_FLOW_HEADER,
		      TEST_NF9_TEMPLATE_ID,
		      TEST_NF9_PRIVATE_FIXLEN);

// Basic flow template IPFIX
static const IPFIX_TEMPLATE(ipvfix_v9_private_template,
			    TEST_IPFIX_FLOW_HEADER,
			    TEST_IPFIX_FIXEDLEN_TEMPLATE_ID,
			    TEST_NF9_PRIVATE_FIXLEN);

static const IPFIX_FLOW(ipvfix_v9_private,
			TEST_IPFIX_FLOW_HEADER,
			TEST_IPFIX_FIXEDLEN_TEMPLATE_ID,
			TEST_NF9_PRIVATE_FIXLEN);

// Variable length private field
static const IPFIX_TEMPLATE(ipvfix_v9_private_varlen_template,
			    TEST_IPFIX_FLOW_HEADER,
			    TEST_IPFIX_VARLEN_TEMPLATE_ID,
			    TEST_NF9_PRIVATE_VARLEN);

// Variable length private field
static const IPFIX_FLOW(ipvfix_v9_private_varlen,
			TEST_IPFIX_FLOW_HEADER,
			TEST_IPFIX_VARLEN_TEMPLATE_ID,
			TEST_NF9_PRIVATE_VARLEN);

#define NF9_PRIVATE_CHECKDATA                                                  \
	{                                                                      \
		{.key = "65", .value = "98"},                                  \
				{.key = "66", .value = "446596"},              \
				{.key = "67", .value = "c02c5e8f0a"},          \
				{.key = "68",                                  \
				 .value = "62b3938e860d4f7c448834ce96b3ca832d" \
					  "85ef54"},                           \
				{.key = "69",                                  \
				 .value = "48e965d989a7e340245c480271caa1"},   \
	}

static const struct checkdata checks = {
		.checks = (const struct checkdata_value[])NF9_PRIVATE_CHECKDATA,
		.size = RD_ARRAYSIZE(((const struct checkdata_value[])
						      NF9_PRIVATE_CHECKDATA)),
};

static int prepare_test_private_nf9(void **state) {
#define TEST(nf_dev_ip, mrecord, mrecord_size, checks, checks_size, ...)       \
	{                                                                      \
		.netflow_src_ip = nf_dev_ip, .record = mrecord,                \
		.record_size = mrecord_size, .checkdata = checks,              \
		.checkdata_size = checks_size, __VA_ARGS__                     \
	}

#define TEST_TEMPLATE_FLOW(                                                    \
		nf_dev_ip, template, template_size, flow, flow_size, ...)      \
	TEST(nf_dev_ip, template, template_size, NULL, 0, __VA_ARGS__)         \
	, TEST(nf_dev_ip, flow, flow_size, &checks, 1, )

	const struct test_params test_params[] = {
			TEST_TEMPLATE_FLOW(0x04030201,
					   &nf9_private_template,
					   sizeof(nf9_private_template),
					   &nf9_private,
					   sizeof(nf9_private),
					   .config_json_path =
							   "./tests/"
							   "0000-testFlowV5."
							   "json", ),
			TEST_TEMPLATE_FLOW(0x04030201,
					   &ipvfix_v9_private_template,
					   sizeof(ipvfix_v9_private_template),
					   &ipvfix_v9_private,
					   sizeof(ipvfix_v9_private), ),
			TEST_TEMPLATE_FLOW(
					0x04030201,
					&ipvfix_v9_private_varlen_template,
					sizeof(ipvfix_v9_private_varlen_template),
					&ipvfix_v9_private_varlen,
					sizeof(ipvfix_v9_private_varlen), ),
	};

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_private_nf9),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
