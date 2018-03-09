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
#include "integration_tests.h"
#include "rb_netflow_test.h"

#include <setjmp.h>

#include <cmocka.h>

#include <fts.h>

/*
  @test Extracting client mac based on flow direction
*/

#ifdef TESTS_ZK_HOST

#define TEST_TEMPLATE_ID 269

#define TEST_IPFIX_HEADER                                                      \
  .unix_secs = constexpr_be32toh(1382637021),                            \
  .flow_sequence = constexpr_be32toh(1080),                              \
  .observation_id = constexpr_be32toh(256),

#define TEST_ENTITIES(RT, R)                                                   \
  RT(IPV4_SRC_ADDR, 4, 0, 10, 13, 122, 44)                               \
  RT(IPV4_DST_ADDR, 4, 0, 66, 220, 152, 19)                              \
  RT(IP_PROTOCOL_VERSION, 1, 0, 4)                                       \
  RT(PROTOCOL, 1, 0, 6)                                                  \
  RT(L4_SRC_PORT, 2, 0, UINT16_TO_UINT8_ARR(54713))                      \
  RT(L4_DST_PORT, 2, 0, UINT16_TO_UINT8_ARR(443))                        \
  RT(FLOW_END_REASON, 1, 0, 3)                                           \
  RT(BIFLOW_DIRECTION, 1, 0, 1)                                          \
  RT(FLOW_SAMPLER_ID, 1, 0, 0)                                           \
  RT(TRANSACTION_ID, UINT64_TO_UINT8_ARR(10332369426321571840))          \
  RT(APPLICATION_ID, 4, 0, FLOW_APPLICATION_ID(13, 453))                 \
  RT(IN_BYTES, 8, 0, UINT64_TO_UINT8_ARR(2744))                          \
  RT(IN_PKTS, 4, 0, UINT32_TO_UINT8_ARR(31))                             \
  RT(FIRST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267193024))               \
  RT(LAST_SWITCHED, 4, 0, UINT32_TO_UINT8_ARR(267261952))

static int prepare_test_nf_template_save0(void **state,
            const void *record,
            size_t record_size,
            const struct checkdata *checkdata,
            size_t checkdata_sz) {
  const struct test_params test_params = {
      .config_json_path = "./tests/0000-testFlowV5.json",
      .zk_url = TESTS_ZK_HOST,
      .templates_zk_node = "/f2k/templates",
      .netflow_src_ip = 0x04030201,
      .record = record,
      .record_size = record_size,
      .checkdata = checkdata,
      .checkdata_size = checkdata_sz};

  *state = prepare_tests(&test_params, 1);
  return *state == NULL;
}

static int prepare_test_nf_template_save(void **state) {
  SKIP_IF_NOT_INTEGRATION;

  return prepare_test_nf_template_save0(
      state, &v10Template, sizeof(v10Template), NULL, 0);
}

static int prepare_test_nf_template_load(void **state) {
  SKIP_IF_NOT_INTEGRATION;

  static const struct checkdata_value checkdata_value[] = {
      {.key = "type", .value = "netflowv10"},
      {.key = "flow_sequence", .value = "1080"},
      {.key = "src", .value = "10.13.122.44"},
      {.key = "dst", .value = "66.220.152.19"},
      {.key = "ip_protocol_version", .value = "4"},
      {.key = "l4_proto", .value = "6"},
      {.key = "src_port", .value = "54713"},
      {.key = "dst_port", .value = "443"},
      {.key = "biflow_direction", .value = "initiator"},
      {.key = "sensor_name", .value = "FlowTest"},
      {.key = "sensor_ip", .value = "4.3.2.1"},
      {.key = "first_switched", .value = "1382636953"},
      {.key = "timestamp", .value = "1382637021"},
      {.key = "bytes", .value = "2744"},
      {.key = "pkts", .value = "31"},
  };

  static const struct checkdata checkdata = {
      .size = RD_ARRAYSIZE(checkdata_value),
      .checks = checkdata_value};

  return prepare_test_nf_template_save0(
      state, &v10Flow, sizeof(v10Flow), &checkdata, 1);
}
#else // TESTS_ZK_HOST

static void skip_test() {
  skip();
}

#endif // TESTS_ZK_HOST

int main() {
#ifdef TESTS_ZK_HOST
  static const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup(testFlow,
                 prepare_test_nf_template_save),
      cmocka_unit_test_setup(testFlow,
                 prepare_test_nf_template_load),
  };
  return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
#else
  static const struct CMUnitTest tests[] = {cmocka_unit_test(skip_test)};
  return cmocka_run_group_tests(tests, NULL, NULL);
#endif // TESTS_ZK_HOST
}
