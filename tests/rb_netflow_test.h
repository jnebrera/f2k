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

#pragma once

#include "config.h"

#include "rb_json_test.h"

#include "rb_netflow_meta.h"

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

int nf_test_setup(void **state);

int nf_test_teardown(void **state);

struct nf_test_state {
#define NF_TEST_STATE_MAGIC 0x355AEA1C355AEA1C
	uint64_t magic;
	struct {
		struct test_params {
			const char *config_json_path;
			const char *mac_vendor_database_path;
			const char *host_list_path;
			const char *geoip_path;
			const char *template_save_path;
#if WITH_ZOOKEEPER
			const char *zk_url;
#endif // WITH_ZOOKEEPER
			const char *kafka_test_producer_url;
			const char *kafka_test_consumer_url;
			const char *kafka_producer_url;
			const char *kafka_consumer_url;
			const char *dns_servers;
			const char *templates_zk_node;
			bool normalize_directions;

			uint32_t netflow_src_ip;

			const void *record;
			size_t record_size;

			const struct checkdata *checkdata;
			size_t checkdata_size;
		} *records;
		size_t records_size;
	} params;
	struct {
		struct string_list **sl;
	} ret;
};

struct nf_test_state *prepare_tests(const struct test_params *test_params,
						size_t test_params_size);

void testFlow(void **state);

/** Try to fail every allocation in testFlow
 * @param vstate Same as testFlow
 */
void mem_test(void **vstate);
