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

#include "rb_lists.h"

#include <string.h>
#include <jansson.h>

/// you have to json_decref(return) when done
void *rb_json_assert_unpack(const char *json, size_t flags,
							const char *fmt,...);

void free_json_unpacked(void *mem);

void free_string_list(struct string_list *sl);

struct checkdata_value{
	const char *key;
	json_type type;
	const char *value;
};

struct checkdata{
	size_t size;
	const struct checkdata_value *checks;
};

void rb_assert_json(const char *str, const size_t size, const struct checkdata *checkdata);

