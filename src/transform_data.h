/**
 * @file transform_data.h
 * @author Jakov Petrina <jakov.petrina@sartura.hr>
 * @brief contains function for transforming
 *
 * @copyright
 * Copyright (C) 2020 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TRANSFORM_DATA_H_ONCE
#define TRANSFORM_DATA_H_ONCE

#include <sysrepo.h>

char *transform_data_boolean_to_zero_one_transform(const char *value, void *private_data);
char *transform_data_zero_one_to_boolean_transform(const char *value, void *private_data);
char *transform_data_boolean_to_zero_one_negated_transform(const char *value, void *private_data);
char *transform_data_zero_one_to_boolean_negated_transform(const char *value, void *private_data);

#endif /* TRANSFORM_DATA_H_ONCE */