#include <inttypes.h>
#include <string.h>

#include <uci.h>

#include "transform_data.h"
#include "utils/memory.h"

char *transform_data_boolean_to_zero_one_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0) {
		return xstrdup("1");
	} else {
		return xstrdup("0");
	}
}

char *transform_data_zero_one_to_boolean_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0) {
		return xstrdup("true");
	} else {
		return xstrdup("false");
	}
}

char *transform_data_boolean_to_zero_one_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0) {
		return xstrdup("0");
	} else {
		return xstrdup("1");
	}
}

char *transform_data_zero_one_to_boolean_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0) {
		return xstrdup("false");
	} else {
		return xstrdup("true");
	}
}