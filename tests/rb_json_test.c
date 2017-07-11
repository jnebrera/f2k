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

#undef NDEBUG
#include "rb_json_test.h"

#include <setjmp.h>

#include <cmocka.h>
/// you have to json_decref(return) when done
void *
rb_json_assert_unpack(const char *json, size_t flags, const char *fmt, ...) {
	json_error_t error;
	json_t *root = json_loads(json, 0, &error);
	if (root == NULL) {
		fail_msg("[EROR PARSING JSON][%s][%s]\n",
			 error.text,
			 error.source);
	}

	va_list args;
	va_start(args, fmt);

	const int unpack_rc = json_vunpack_ex(root, &error, flags, fmt, args);

	if (unpack_rc != 0 /* Failure */) {
		fail_msg("[ERROR UNPACKING][%s][%s]\n",
			 error.text,
			 error.source);
	}

	va_end(args);

	return root;
}

void free_json_unpacked(void *mem) {
	json_decref(mem);
}

void free_string_list(struct string_list *sl) {
	struct string_list *aux = sl;
	while (sl) {
		aux = sl->next;
		printbuf_free(sl->string);
		free(sl);
		sl = aux;
	}
}

static void assertEqual(const int64_t a,
			const int64_t b,
			const char *key,
			const char *src) {
	if (a != b) {
		fail_msg("[%s integer value mismatch] Actual: %ld, Expected:"
			 " %ld in %s\n",
			 key,
			 a,
			 b,
			 src);
	}
}

static void rb_assert_json_value(const struct checkdata_value *chk_value,
				 const json_t *json_value,
				 const char *src) {
	// assert(chk_value->type == json_typeof(json_value));
	if (chk_value->value == NULL && json_value == NULL) {
		return; // All ok
	}

	if (chk_value->value == NULL && json_value != NULL) {
		fail_msg("Json key %s with value %s, should not exists in "
			 "(%s)\n",
			 chk_value->key,
			 json_string_value(json_value),
			 src);
	}

	if (NULL == json_value) {
		fail_msg("Json value %s does not exists in %s\n",
			 chk_value->key,
			 src);
	}
	switch (json_typeof(json_value)) {
	case JSON_INTEGER: {
		const json_int_t json_int_value =
				json_integer_value(json_value);
		const long chk_int_value = atol(chk_value->value);
		assertEqual(json_int_value, chk_int_value, chk_value->key, src);
	} break;
	case JSON_STRING: {
		const char *json_str_value = json_string_value(json_value);
		assert_non_null(json_str_value);
		assert_string_equal(json_str_value, chk_value->value);
	} break;
	default:
		fail_msg("You should not be here");
	}
}

void rb_assert_json(const char *str,
		    const size_t size,
		    const struct checkdata *checkdata) {
	size_t i = 0;
	json_error_t error;
	json_t *root = json_loadb(str, size, 0, &error);
	if (root == NULL) {
		fail_msg("[EROR PARSING JSON][%s][%s]\n",
			 error.text,
			 error.source);
	}

	for (i = 0; i < checkdata->size; ++i) {
		const json_t *json_value =
				json_object_get(root, checkdata->checks[i].key);
		rb_assert_json_value(&checkdata->checks[i], json_value, str);
	}

	json_decref(root);
}
