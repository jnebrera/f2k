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

// clang-format off
static const NetFlow5Record record = {
	.flowHeader = {
		.version = 0x0500,     // Current version=5
		.count = 0x0100,       // The number of records in PDU.
		.sys_uptime = 12345,    // Current time in msecs since router booted
		.unix_secs = 12345,    // Current seconds since 0000 UTC 1970
		.unix_nsecs = 12345,   // Residual nanoseconds since 0000 UTC 1970
		.flow_sequence = 1050, // Sequence number of total flows seen
		.engine_type = 0,      // Type of flow switching engine (RP,VIP,etc.)
		.engine_id  = 0,       // Slot number of the flow switching engine
		.sampleRate = 0,       // Packet capture sample rate
	},

	.flowRecord = {
		// Second: Source belongs to home net from ANOTHER sensors
		[0] = {
			.srcaddr = 0x0a1e000aL,
			.dstaddr = 0x0201a8c0L,
			.nexthop = 0x00000000L,
			.input   = 0,
			.output  = 255,
			.dPkts   = 0x0100,
			.dOctets = 0x4600,

			.first   = 0xa8484205,
			.last    = 0xa8484205,
			.srcport = constexpr_be16toh(443),
			.dstport = constexpr_be16toh(10101),
			.pad1    = 0,
			.tcp_flags = 0,
			.proto   = 0,
			.tos     = 0,
			.src_as  = 0,
			.dst_as  = 0,
			.src_mask = 0,
			.dst_mask = 0,
			.pad2    = 0,
		},
	}
};

// clang-format on

static int prepare_test_nf5_enrichment(void **state) {
	static const struct checkdata_value checkdata_values1 = {
			.key = "testing", .value = "abc"};

	static const struct checkdata checkdata = {
			.size = 1, .checks = &checkdata_values1};

	static const struct test_params test_params = {
			.config_json_path =
					"./tests/0026-testEnrichmentV5.json",
			.host_list_path = "./tests/0011-data/",
			.netflow_src_ip = 0x04030301,
			.record = &record,
			.record_size = sizeof(record),
			.checkdata = &checkdata,
			.checkdata_size = 1};

	*state = prepare_tests(&test_params, 1);
	return *state == NULL;
}

int main() {
	static const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup(testFlow,
					       prepare_test_nf5_enrichment),
	};

	return cmocka_run_group_tests(tests, nf_test_setup, nf_test_teardown);
}
