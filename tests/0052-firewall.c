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

#define TEST_TEMPLATE_ID 256

#define TEST_FIREWALL_BASE_0(RT, R)                                            \
	RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(98))                            \
	RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(1))                              \
	RT(PROTOCOL, 1, 0, 1)                                                  \
	RT(SRC_TOS, 1, 0, 0)                                                   \
	RT(TCP_FLAGS, 1, 0, 0x00)                                              \
	RT(L4_SRC_PORT, 2, 0, 0x00, 0x00)

#define TEST_FIREWALL_BASE_1(RT, R)                                            \
	RT(INPUT_SNMP, 4, 0, 0x00, 0x00, 0x00, 0x00)                           \
	RT(L4_DST_PORT, 2, 0, 0x00, 0x00)

#define TEST_FIREWALL_BASE_2(RT, R, t_icmp_type, t_flow_id, t_fw_event)        \
	RT(OUTPUT_SNMP, 4, 0, 0x00, 0x00, 0x00, 0x04)                          \
	RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000))                  \
	RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(400000))                   \
	RT(ICMP_TYPE, 2, 0, UINT16_TO_UINT8_ARR(t_icmp_type))                  \
	RT(DIRECTION, 1, 0, 0)                                                 \
	RT(FLOW_ID, 8, 0, UINT64_TO_UINT8_ARR(t_flow_id))                      \
	RT(FIREWALL_EVENT, 1, 0, t_fw_event)

#define TEST_FIREWALL_BASE_IPV4(RT, R, t_icmp_type, t_flow_id, t_fw_event)     \
	TEST_FIREWALL_BASE_0(RT, R)                                            \
	RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 94, 223)                               \
	TEST_FIREWALL_BASE_1(RT, R)                                            \
	RT(IPV4_DST_ADDR, 4, 0, 10, 13, 94, 223)                               \
	TEST_FIREWALL_BASE_2(RT, R, t_icmp_type, t_flow_id, t_fw_event)

#define TEST_ICMP_TYPE_ENTITIES_1(RT, R)                                       \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 599, 0)
#define TEST_ICMP_TYPE_ENTITIES_2(RT, R)                                       \
	TEST_FIREWALL_BASE_IPV4(RT, R, 265, 599, 0)

// Basic flow template
static const NF9_TEMPLATE(firewall_base_template,
			  TEST_FLOW_HEADER,
			  TEST_TEMPLATE_ID,
			  TEST_ICMP_TYPE_ENTITIES_1);

#define FIREWALL_CHECKDATA(t_icmp_type, t_flow_id, t_fw_event)                 \
	{                                                                      \
			{.key = "type", .value = "netflowv9"},                 \
			{.key = "icmp_type", .value = #t_icmp_type},           \
			{.key = "flow_id", .value = #t_flow_id},               \
			{.key = "firewall_event", .value = t_fw_event},        \
	};

static int prepare_test_firewall_base(const void *v9_template,
				      size_t v9_template_size,
				      const void *v9_flow,
				      size_t v9_flow_size,
				      const struct checkdata *checkdata,
				      size_t checkdata_size,
				      void **state) {
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
		     v9_template,
		     v9_template_size,
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
			FIREWALL_CHECKDATA(0, 599, NULL);

	static const struct checkdata_value checkdata2[] =
			FIREWALL_CHECKDATA(265, 599, NULL);

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
	};

	return prepare_test_firewall_base(&firewall_base_template,
					  sizeof(firewall_base_template),
					  &it_flow,
					  sizeof(it_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

#define TEST_FLOW_ID_ENTITIES_1(RT, R) TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 0)
#define TEST_FLOW_ID_ENTITIES_2(RT, R) TEST_FIREWALL_BASE_IPV4(RT, R, 0, 599, 0)
static int prepare_test_firewall_flow_id(void **state) {
	static const FIREWALL_TWO_FLOWS(it_flow,
					TEST_FLOW_HEADER,
					TEST_TEMPLATE_ID,
					TEST_FLOW_ID_ENTITIES_1,
					TEST_FLOW_ID_ENTITIES_2);

	static const struct checkdata_value checkdata1[] =
			FIREWALL_CHECKDATA(0, 0, NULL);

	static const struct checkdata_value checkdata2[] =
			FIREWALL_CHECKDATA(0, 599, NULL);

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
	};

	return prepare_test_firewall_base(&firewall_base_template,
					  sizeof(firewall_base_template),
					  &it_flow,
					  sizeof(it_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

#define TEST_FW_EVENT_ZERO_ENTITIES(RT, R)                                     \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 0)
#define TEST_FW_EVENT_CREATED_ENTITIES(RT, R)                                  \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 1)
#define TEST_FW_EVENT_DELETED_ENTITIES(RT, R)                                  \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 2)
#define TEST_FW_EVENT_DENIED_ENTITIES(RT, R)                                   \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 3)
#define TEST_FW_EVENT_ALERT_ENTITIES(RT, R)                                    \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 4)
#define TEST_FW_EVENT_UPDATE_ENTITIES(RT, R)                                   \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 5)
#define TEST_FW_EVENT_INVALID_ENTITIES(RT, R)                                  \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 0, 6)
static int prepare_test_firewall_fw_event(void **state) {
	static const struct {
		V9FlowHeader flow_header;
		struct {
			V9TemplateHeader flow_set_header;
			uint8_t buffer[FLOW_BYTES_LENGTH(
					TEST_FW_EVENT_ZERO_ENTITIES)];
		} __attribute__((packed)) flowset[7];
	} __attribute__((packed))
	it_flow = {.flow_header = {.version = constexpr_be16toh(9),
				   .unix_secs = constexpr_be32toh(1520362144),
				   .count = constexpr_be16toh(7),
				   TEST_FLOW_HEADER},
		   // clang-format off
	 .flowset = {
		ONE_FLOW_FLOWSET(TEST_TEMPLATE_ID,
				 TEST_FW_EVENT_ZERO_ENTITIES),
		ONE_FLOW_FLOWSET(TEST_TEMPLATE_ID,
				 TEST_FW_EVENT_CREATED_ENTITIES),
		ONE_FLOW_FLOWSET(TEST_TEMPLATE_ID,
				 TEST_FW_EVENT_DELETED_ENTITIES),
		ONE_FLOW_FLOWSET(TEST_TEMPLATE_ID,
				 TEST_FW_EVENT_DENIED_ENTITIES),
		ONE_FLOW_FLOWSET(TEST_TEMPLATE_ID,
				 TEST_FW_EVENT_ALERT_ENTITIES),
		ONE_FLOW_FLOWSET(TEST_TEMPLATE_ID,
				 TEST_FW_EVENT_UPDATE_ENTITIES),
		ONE_FLOW_FLOWSET(TEST_TEMPLATE_ID,
				 TEST_FW_EVENT_INVALID_ENTITIES),
				   // clang-format on
		   }};

	static const struct checkdata_value checkdata1[] =
			FIREWALL_CHECKDATA(0, 0, NULL);

	static const struct checkdata_value checkdata2[] =
			FIREWALL_CHECKDATA(0, 0, "Created");

	static const struct checkdata_value checkdata3[] =
			FIREWALL_CHECKDATA(0, 0, "Deleted");

	static const struct checkdata_value checkdata4[] =
			FIREWALL_CHECKDATA(0, 0, "Denied");

	static const struct checkdata_value checkdata5[] =
			FIREWALL_CHECKDATA(0, 0, "Alert");

	static const struct checkdata_value checkdata6[] =
			FIREWALL_CHECKDATA(0, 0, "Update");

	static const struct checkdata_value checkdata7[] =
			FIREWALL_CHECKDATA(0, 0, NULL);

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
			{.size = RD_ARRAYSIZE(checkdata3),
			 .checks = checkdata3},
			{.size = RD_ARRAYSIZE(checkdata4),
			 .checks = checkdata4},
			{.size = RD_ARRAYSIZE(checkdata5),
			 .checks = checkdata5},
			{.size = RD_ARRAYSIZE(checkdata6),
			 .checks = checkdata6},
			{.size = RD_ARRAYSIZE(checkdata7),
			 .checks = checkdata7},
	};

	return prepare_test_firewall_base(&firewall_base_template,
					  sizeof(firewall_base_template),
					  &it_flow,
					  sizeof(it_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

#define TEST_FIREWALL_NAT_PORTS(RT, R, pnat_src_port, pnat_dst_port)           \
	RT(POST_NAT_SRC_L4_PORT, 2, 0, UINT16_TO_UINT8_ARR(pnat_src_port))     \
	RT(POST_NAT_DST_L4_PORT, 2, 0, UINT16_TO_UINT8_ARR(pnat_dst_port))

#define NAT_CHECKDATA(t_version,                                               \
		      t_post_src_addr,                                         \
		      t_post_dst_addr,                                         \
		      t_post_src_port,                                         \
		      t_post_dst_port)                                         \
	{                                                                      \
		{.key = "type", .value = "netflowv9"},                         \
				{.key = "post_nat_src_ipv" t_version "_addr",  \
				 .value = t_post_src_addr},                    \
				{.key = "post_nat_dst_ipv" t_version "_addr",  \
				 .value = t_post_dst_addr},                    \
				{.key = "post_nat_src_l4_port",                \
				 .value = t_post_src_port},                    \
				{.key = "post_nat_dst_l4_port",                \
				 .value = t_post_dst_port},                    \
	}

static int prepare_test_firewall_post_nat4(void **state) {
#define TEST_FIREWALL_NAT_V4_ENTITIES_1(RT, R)                                 \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 10, 0)                               \
	RT(POST_NAT_SRC_IPV4_ADDR, 4, 0, 0, 0, 0, 0)                           \
	RT(POST_NAT_DST_IPV4_ADDR, 4, 0, 0, 0, 0, 0)                           \
	TEST_FIREWALL_NAT_PORTS(RT, R, 0, 0)

#define TEST_FIREWALL_NAT_V4_ENTITIES_2(RT, R)                                 \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 10, 0)                               \
	RT(POST_NAT_SRC_IPV4_ADDR, 4, 0, 8, 8, 2, 3)                           \
	RT(POST_NAT_DST_IPV4_ADDR, 4, 0, 8, 8, 4, 4)                           \
	TEST_FIREWALL_NAT_PORTS(RT, R, 53, 10053)

	static const NF9_TEMPLATE(nat_v4_template,
				  TEST_FLOW_HEADER,
				  TEST_TEMPLATE_ID,
				  TEST_FIREWALL_NAT_V4_ENTITIES_1);

	static const FIREWALL_TWO_FLOWS(it_flow,
					TEST_FLOW_HEADER,
					TEST_TEMPLATE_ID,
					TEST_FIREWALL_NAT_V4_ENTITIES_1,
					TEST_FIREWALL_NAT_V4_ENTITIES_2);

	static const struct checkdata_value checkdata1[] =
			NAT_CHECKDATA("4", "0.0.0.0", "0.0.0.0", "0", "0");

	static const struct checkdata_value checkdata2[] =
			NAT_CHECKDATA("4", "8.8.2.3", "8.8.4.4", "53", "10053");

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
	};

	return prepare_test_firewall_base(&nat_v4_template,
					  sizeof(nat_v4_template),
					  &it_flow,
					  sizeof(it_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

static int prepare_test_firewall_post_nat6(void **state) {
// clang-format off
#define TEST_FIREWALL_NAT_V6_ENTITIES_1(RT, R)                                 \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 10, 0)                               \
	RT(POST_NAT_SRC_IPV6_ADDR, 16, 0, 0, 0, 0, 0,                         \
		                          0, 0, 0, 0,                         \
		                          0, 0, 0, 0,                         \
		                          0, 0, 0, 0)                         \
	RT(POST_NAT_DST_IPV6_ADDR, 16, 0, 0, 0, 0, 0,                         \
		                          0, 0, 0, 0,                         \
		                          0, 0, 0, 0,                         \
		                          0, 0, 0, 0)                         \
	TEST_FIREWALL_NAT_PORTS(RT, R, 0, 0)

#define TEST_FIREWALL_NAT_V6_ENTITIES_2(RT, R)                                 \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 10, 0)                               \
	RT(POST_NAT_SRC_IPV6_ADDR, 16, 0, 0x20, 0x01, 0x0d, 0xb8,             \
		                          0x0a, 0x0b, 0x12, 0xf0,             \
		                          0x00, 0x00, 0x00, 0x00,             \
		                          0x00, 0x00, 0x00, 0x01)             \
	RT(POST_NAT_DST_IPV6_ADDR, 16, 0, 0x20, 0x01, 0x0d, 0xb8,             \
		                          0x0a, 0x0b, 0x12, 0xf0,             \
		                          0x00, 0x00, 0x00, 0x00,             \
		                          0x00, 0x00, 0x00, 0x02)             \
	TEST_FIREWALL_NAT_PORTS(RT, R, 53, 10053)
	// clang-format on

	static const NF9_TEMPLATE(nat_v6_template,
				  TEST_FLOW_HEADER,
				  TEST_TEMPLATE_ID,
				  TEST_FIREWALL_NAT_V6_ENTITIES_1);

	static const FIREWALL_TWO_FLOWS(it_flow,
					TEST_FLOW_HEADER,
					TEST_TEMPLATE_ID,
					TEST_FIREWALL_NAT_V6_ENTITIES_1,
					TEST_FIREWALL_NAT_V6_ENTITIES_2);

	static const struct checkdata_value checkdata1[] =
			NAT_CHECKDATA("6",
				      "0000:0000:0000:0000:0000:0000:0000:0000",
				      "0000:0000:0000:0000:0000:0000:0000:0000",
				      "0",
				      "0");

	static const struct checkdata_value checkdata2[] =
			NAT_CHECKDATA("6",
				      "2001:0db8:0a0b:12f0:0000:0000:0000:0001",
				      "2001:0db8:0a0b:12f0:0000:0000:0000:0002",
				      "53",
				      "10053");

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
	};

	return prepare_test_firewall_base(&nat_v6_template,
					  sizeof(nat_v6_template),
					  &it_flow,
					  sizeof(it_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

static int prepare_test_firewall_appid_username(void **state) {

	// Note that app_id and username are fixed length, so provided buffers
	// needs to be that way
#define TEST_FIREWALL_APPID_USERNAME_ENTITIES(RT, R, app_id, username)         \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 10, 0)                               \
	RT(346 /*Enterprise private number */,                                 \
	   4,                                                                  \
	   0,                                                                  \
	   UINT32_TO_UINT8_ARR(25461))                                         \
	RT(PALOALTO_APP_ID, 32, 0, app_id)                                     \
	RT(PALOALTO_USERNAME, 64, 0, username)

// clang-format off
#define ZERO16 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define ZERO_APP_ID ZERO16, ZERO16
#define ZERO_USERNAME ZERO_APP_ID, ZERO_APP_ID

#define DNS_APP_ID 'd', 'n', 's', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ZERO16

#define USER1_USERNAME 'u', 's', 'e', 'r', '1', 0, 0, 0, \
	               0, 0, 0, 0, 0, 0, 0, 0, ZERO16, ZERO16, ZERO16
	// clang-format on

#define TEST_FIREWALL_APPID_USERNAME_ENTITIES_1(RT, R)                         \
	TEST_FIREWALL_APPID_USERNAME_ENTITIES(RT, R, ZERO_APP_ID, ZERO_USERNAME)

#define TEST_FIREWALL_APPID_USERNAME_ENTITIES_2(RT, R)                         \
	TEST_FIREWALL_APPID_USERNAME_ENTITIES(RT, R, DNS_APP_ID, USER1_USERNAME)

#define APPID_USERNAME_CHECKDATA(t_checkdata, t_username)                      \
	{                                                                      \
		{.key = "type", .value = "netflowv9"},                         \
				{.key = "app_id_name", .value = t_checkdata},  \
				{.key = "user", .value = t_username},          \
	}

	static const NF9_TEMPLATE(v9_template,
				  TEST_FLOW_HEADER,
				  TEST_TEMPLATE_ID,
				  TEST_FIREWALL_APPID_USERNAME_ENTITIES_1);

	static const FIREWALL_TWO_FLOWS(
			v9_flow,
			TEST_FLOW_HEADER,
			TEST_TEMPLATE_ID,
			TEST_FIREWALL_APPID_USERNAME_ENTITIES_1,
			TEST_FIREWALL_APPID_USERNAME_ENTITIES_2);

	static const struct checkdata_value checkdata1[] =
			APPID_USERNAME_CHECKDATA(NULL, NULL);

	static const struct checkdata_value checkdata2[] =
			APPID_USERNAME_CHECKDATA("dns", "user1");

	static const struct checkdata it_checkdata[] = {
			{.size = RD_ARRAYSIZE(checkdata1),
			 .checks = checkdata1},
			{.size = RD_ARRAYSIZE(checkdata2),
			 .checks = checkdata2},
	};

	return prepare_test_firewall_base(&v9_template,
					  sizeof(v9_template),
					  &v9_flow,
					  sizeof(v9_flow),
					  it_checkdata,
					  RD_ARRAYSIZE(it_checkdata),
					  state);
}

static int prepare_test_forwarding_status(void **state) {
#define NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, t_forward_status)              \
	TEST_FIREWALL_BASE_IPV4(RT, R, 0, 1020, 0)                             \
	RT(FORWARDING_STATUS, 1, 0, t_forward_status)

#define NF9_FORWARDING_STATUS_ENTITIES_TEMPLATE(RT, R)                         \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0)

#define NF9_FORWARDING_STATUS_ENTITIES_UNKNOWN(RT, R)                          \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0)                             \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 1)    /* Invalid */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x3f) /* Invalid "negative" */

#define NF9_FORWARDING_STATUS_ENTITIES_FORWARDED(RT, R)                        \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x40) /* Unknown */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x41) /* Fragmented */         \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x42) /* Not Fragmented */     \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x43) /* Tunneled */           \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x44) /* Invalid */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x7f) /* "Invalid negative" */

#define NF9_FORWARDING_STATUS_ENTITIES_DROPPED_0(RT, R)                        \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x80) /* Unknown */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x81) /* ACL deny */           \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x82) /* ACL drop */           \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x83) /* Unroutable */         \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x84) /* Adjacency */          \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x85) /* Fragmentation and DF  \
							 set */                \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x86) /* Bad header checksum   \
						       */                      \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x87) /* Bad total Length */   \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x88) /* Bad header length */

#define NF9_FORWARDING_STATUS_ENTITIES_DROPPED_1(RT, R)                        \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x89) /* bad TTL */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x8A) /* Policer */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x8B) /* WRED */               \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x8C) /* RPF */                \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x8D) /* For us */             \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x8E) /* Bad output interface  \
						       */                      \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x8F) /* Hardware */           \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0x90) /* Invalid */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0xbf) /* Invalid "negative" */

#define NF9_FORWARDING_STATUS_ENTITIES_CONSUMED(RT, R)                         \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0xC0) /* Unknown */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0xC1) /* Punt Adjacency */     \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0xC2) /* Incomplete Adjacency  \
						       */                      \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0xC3) /* For us */             \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0xC4) /* Invalid */            \
	NF9_FORWARDING_STATUS_ENTITIES_0(RT, R, 0xFF) /* Invalid negative */

#define FORWARDING_STATUS_CHECKDATA_VALUES(t_forward_status,                   \
					   t_forward_status_reason)            \
	{                                                                      \
		{.key = "forwarding_status", .value = t_forward_status},       \
				{.key = "forwarding_status_reason",            \
				 .value = t_forward_status_reason},            \
	}
#define FORWARDING_STATUS_CHECKDATA(t_check)                                   \
	{ .size = 2, .checks = t_check }

	static const NF9_TEMPLATE(forwarding_status_template,
				  TEST_FLOW_HEADER,
				  TEST_TEMPLATE_ID,
				  NF9_FORWARDING_STATUS_ENTITIES_TEMPLATE);

	// Don't use one flow per flowset in this template anymore
	static const NF9_FLOW(unknown_forwarding_status_flow,
			      TEST_FLOW_HEADER,
			      TEST_TEMPLATE_ID,
			      NF9_FORWARDING_STATUS_ENTITIES_UNKNOWN);

	static const struct checkdata_value unknown_checkdata_values[] =
			FORWARDING_STATUS_CHECKDATA_VALUES("Unknown", NULL);

	static const struct checkdata unknown_checkdata[] = {
			FORWARDING_STATUS_CHECKDATA(unknown_checkdata_values),
			FORWARDING_STATUS_CHECKDATA(unknown_checkdata_values),
			FORWARDING_STATUS_CHECKDATA(unknown_checkdata_values),
	};

	static const NF9_FLOW(forwarded_forwarding_status_flow,
			      TEST_FLOW_HEADER,
			      TEST_TEMPLATE_ID,
			      NF9_FORWARDING_STATUS_ENTITIES_FORWARDED);

	// clang-format off
	static const struct checkdata_value forwarded_checkdata_values[][2] = {
		FORWARDING_STATUS_CHECKDATA_VALUES("Forwarded", "Unknown"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Forwarded", "Fragmented"),
		FORWARDING_STATUS_CHECKDATA_VALUES(
						  "Forwarded","Not fragmented"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Forwarded", "Tunneled"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Forwarded", "68"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Forwarded", "127"),
	};

	static const struct checkdata forwarded_checkdata[] = {
		FORWARDING_STATUS_CHECKDATA(forwarded_checkdata_values[0]),
		FORWARDING_STATUS_CHECKDATA(forwarded_checkdata_values[1]),
		FORWARDING_STATUS_CHECKDATA(forwarded_checkdata_values[2]),
		FORWARDING_STATUS_CHECKDATA(forwarded_checkdata_values[3]),
		FORWARDING_STATUS_CHECKDATA(forwarded_checkdata_values[4]),
		FORWARDING_STATUS_CHECKDATA(forwarded_checkdata_values[5]),
	};
	// clang-format on

	static const NF9_FLOW(dropped_0_forwarding_status_flow,
			      TEST_FLOW_HEADER,
			      TEST_TEMPLATE_ID,
			      NF9_FORWARDING_STATUS_ENTITIES_DROPPED_0);

	static const NF9_FLOW(dropped_1_forwarding_status_flow,
			      TEST_FLOW_HEADER,
			      TEST_TEMPLATE_ID,
			      NF9_FORWARDING_STATUS_ENTITIES_DROPPED_1);

	// clang-format off
	static const struct checkdata_value dropped_checkdata_values[][2] = {
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "Unknown"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "ACL deny"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "ACL drop"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "Unroutable"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "Adjacency"),
		FORWARDING_STATUS_CHECKDATA_VALUES(
					 "Dropped", "Fragmentation and DF set"),
		FORWARDING_STATUS_CHECKDATA_VALUES(
					 "Dropped", "Bad header checksum"),
		FORWARDING_STATUS_CHECKDATA_VALUES(
					 "Dropped", "Bad total length"),
		FORWARDING_STATUS_CHECKDATA_VALUES(
					 "Dropped", "Bad header length"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "Bad TTL"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "Policer"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "WRED"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "RPF"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "For us"),
		FORWARDING_STATUS_CHECKDATA_VALUES(
			                     "Dropped", "Bad output interface"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "Hardware"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "144"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Dropped", "191"),
	};

	static const struct checkdata dropped_checkdata_0[] = {
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[0]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[1]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[2]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[3]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[4]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[5]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[6]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[7]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[8]),
	};

	static const struct checkdata dropped_checkdata_1[] = {
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[9]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[10]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[11]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[12]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[13]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[14]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[15]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[16]),
		FORWARDING_STATUS_CHECKDATA(dropped_checkdata_values[17]),
	};
	// clang-format on

	static const NF9_FLOW(consumed_forwarding_status_flow,
			      TEST_FLOW_HEADER,
			      TEST_TEMPLATE_ID,
			      NF9_FORWARDING_STATUS_ENTITIES_CONSUMED);

	// clang-format off
	static const struct checkdata_value consumed_checkdata_values[][2] = {
		FORWARDING_STATUS_CHECKDATA_VALUES("Consumed", "Unknown"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Consumed",
						   "Punt adjacency"),
		FORWARDING_STATUS_CHECKDATA_VALUES(
					"Consumed", "Incomplete adjacency"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Consumed", "For us"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Consumed", "196"),
		FORWARDING_STATUS_CHECKDATA_VALUES("Consumed", "255"),
	};

	static const struct checkdata consumed_checkdata[] = {
		FORWARDING_STATUS_CHECKDATA(consumed_checkdata_values[0]),
		FORWARDING_STATUS_CHECKDATA(consumed_checkdata_values[1]),
		FORWARDING_STATUS_CHECKDATA(consumed_checkdata_values[2]),
		FORWARDING_STATUS_CHECKDATA(consumed_checkdata_values[3]),
		FORWARDING_STATUS_CHECKDATA(consumed_checkdata_values[4]),
		FORWARDING_STATUS_CHECKDATA(consumed_checkdata_values[5]),
	};
	// clang-format on

	// clang-format off
	const struct test_params test_params[] = {
		TEST("./tests/0000-testFlowV5.json",
		     "./tests/0009-data/",
		     &forwarding_status_template,
		     sizeof(forwarding_status_template),
		     NULL,
		     0),

		TEST(NULL,
		     NULL,
		     &unknown_forwarding_status_flow,
		     sizeof(unknown_forwarding_status_flow),
		     unknown_checkdata,
		     RD_ARRAYSIZE(unknown_checkdata)),

		TEST(NULL,
		     NULL,
		     &forwarded_forwarding_status_flow,
		     sizeof(forwarded_forwarding_status_flow),
		     forwarded_checkdata,
		     RD_ARRAYSIZE(forwarded_checkdata)),

		TEST(NULL,
		     NULL,
		     &dropped_0_forwarding_status_flow,
		     sizeof(dropped_0_forwarding_status_flow),
		     dropped_checkdata_0,
		     RD_ARRAYSIZE(dropped_checkdata_0)),

		TEST(NULL,
		     NULL,
		     &dropped_1_forwarding_status_flow,
		     sizeof(dropped_1_forwarding_status_flow),
		     dropped_checkdata_1,
		     RD_ARRAYSIZE(dropped_checkdata_1)),

		TEST(NULL,
		     NULL,
		     &consumed_forwarding_status_flow,
		     sizeof(consumed_forwarding_status_flow),
		     consumed_checkdata,
		     RD_ARRAYSIZE(consumed_checkdata)),
	};
	// clang-format on

	*state = prepare_tests(test_params, RD_ARRAYSIZE(test_params));
	return *state == NULL;
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_firewall_icmp_type),
			cmocka_unit_test_setup(testFlow,
					       prepare_test_firewall_flow_id),
			cmocka_unit_test_setup(testFlow,
					       prepare_test_firewall_fw_event),
			cmocka_unit_test_setup(testFlow,
					       prepare_test_firewall_post_nat4),
			cmocka_unit_test_setup(testFlow,
					       prepare_test_firewall_post_nat6),
			cmocka_unit_test_setup(
					testFlow,
					prepare_test_firewall_appid_username),
			cmocka_unit_test_setup(testFlow,
					       prepare_test_forwarding_status),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
