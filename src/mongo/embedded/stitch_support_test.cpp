/**
 *    Copyright (C) 2018 MongoDB Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the GNU Affero General Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */


#include "mongo/embedded/stitch_support.h"

#include "mongo/db/json.h"

static const char thumbs_up[] = {static_cast<char>(0xF0),
                                 static_cast<char>(0x9F),
                                 static_cast<char>(0x91),
                                 static_cast<char>(0x8D),
                                 0x00};

static const char thumbs_down[] = {static_cast<char>(0xF0),
                                   static_cast<char>(0x9F),
                                   static_cast<char>(0x91),
                                   static_cast<char>(0x8E),
                                   0x00};

/**
 * This JSON parsing function is intended for testing, not for parsing user input. It aborts if it
 * fails to parse its input or if there is not enough buffer space for the output.
 */
static const char* parseJSONToBufferOrDie(const char* json_string, char* out, size_t out_size) {
    int parsed_len = 0;

    // This may throw an exception, which will be left uncaught, also aborting the program.
    auto bson = mongo::fromjson(json_string, &parsed_len);

    if (parsed_len != static_cast<int>(strlen(json_string)) ||
        static_cast<size_t>(bson.objsize()) > out_size) {
        fprintf(stderr, "FATAL -- Failed to parse: \"%s\"\n", json_string);
        abort();
    }

    memcpy(out, bson.objdata(), bson.objsize());

    return out;
}

/**
 * This JSON parsing function is intended for testing, not for parsing user input. It aborts if it
 * fails to parse its input or if there is not enough buffer space for the output.
 *
 * Returns a pointer to a static buffer. This function is not thread safe, and clients that need
 * long-term access to the resulting BSON should copy it to another location.
 */
static const char* parseJSONOrDie(const char* json_string) {
    static char out_buffer[4096];

    parseJSONToBufferOrDie(json_string, out_buffer, sizeof(out_buffer));

    return out_buffer;
}

/**
 * This JSON formatting function is intended for testing. It aborts if input is not well-formed
 * BSON.
 *
 * Returns a pointer to a static buffer. This function is not thread safe, and clients that need
 * long-term access to the resulting string should copy it to another location.
 */
static const char* formatAsJSONOrDie(char* bsonData) {
    static char str_output[4096];
    mongo::BSONObj bson(bsonData);

    auto jsonStr = mongo::tojson(bson);

    // Weird, there's no strlcpy linked into this binary!
    strncpy(str_output, jsonStr.c_str(), sizeof(str_output));
    str_output[sizeof(str_output) - 1] = '\0';

    return str_output;
}

struct match_test {
    const char* predicate;
    const char* document;

    bool expectedResult;
    const char* expectedElemMatchPath;
};

static struct match_test match_test_cases[] = {
    {"{a: 1}", "{a: 1, b: 1}", true, NULL},
    {"{a: 1}", "{a: [0, 1]}", true, "a"},
    {"{'a.b': 1}", "{a: {b: 1}}", true, NULL},
    {"{'a.b': 1}", "{a: [{b: 1}]}", true, "a"},
    {"{'a.b': 1}", "{a: {b: [0, 1]}}", true, "a, b"},
    {"{'a.b': 1}", "{a: [{b: [0, 1]}]}", true, "a"},
    {"{'a.0.b': 1}", "{a: [{b: 1}]}", true, NULL},
    {"{'a.0.b': 1}", "{a: [{b: [0, 1]}]}", true, "a, 0, b"},
    {"{'a.1.b': 1}", "{a: [{b: [0, 1]}, {b: [0, 1]}]}", true, "a, 1, b"},
    {"{a: {$size: 1}}", "{a: [100]}", true, NULL},
    {"{a: {$size: 1}}", "{a: [[100], [101]]}", false, NULL},
    {"{'a.b': {$size: 1}}", "{a: [0, {b: [100]}]}", true, "a"},
    {"{'a.1.0.b': 1}", "{a: [123, [{b: [1]}, 456]]}", true, "a, 1, 0, b"},
    {"{'a.1.b': 1}", "{a: [123, [{b: [1]}, 456]]}", true, "a, 1"},
};

static size_t num_match_test_cases = sizeof(match_test_cases) / sizeof(match_test_cases[0]);

static bool run_match_tests(mongo_embedded_v1_lib* lib) {
    printf("Match test cases\n");

    int num_failures = 0;
    mongo_embedded_v1_status* status = mongo_embedded_v1_status_create();
    mongo_embedded_v1_match_details* match_details = mongo_embedded_v1_match_details_create();

    for (size_t i = 0; i < num_match_test_cases; ++i) {
        match_test* test = &match_test_cases[i];
        bool isMatch = false;
        mongo_embedded_v1_matcher* matcher =
            mongo_embedded_v1_matcher_create(lib, parseJSONOrDie(test->predicate), status);

        if (!matcher) {
            fprintf(stderr,
                    "Failed to create matcher: %s\n",
                    mongo_embedded_v1_status_get_explanation(status));
            goto fail;
        }

        if (MONGO_EMBEDDED_V1_SUCCESS !=
            mongo_embedded_v1_check_match(
                matcher, parseJSONOrDie(test->document), &isMatch, match_details, status)) {
            fprintf(stderr,
                    "Failed to check match: %s\n",
                    mongo_embedded_v1_status_get_explanation(status));
            goto fail;
        }

        if (isMatch) {
            if (!test->expectedResult) {
                fprintf(stderr, "Unexpected match\n");
                goto fail;
            }

            if (mongo_embedded_v1_match_details_has_elem_match_path(match_details)) {
                if (!test->expectedElemMatchPath) {
                    fprintf(stderr, "Unexpected elemMatchPath\n");
                    goto fail;
                }

                // Dump the elemMatchPath to a string.
                char elem_match_path_str[1024];
                int bytes_left = sizeof(elem_match_path_str);
                char* out_str = elem_match_path_str;

                int path_length =
                    mongo_embedded_v1_match_details_elem_match_path_length(match_details);
                for (int j = 0; j < path_length; ++j) {
                    int bytes_written =
                        snprintf(out_str,
                                 bytes_left,
                                 "%s%s",
                                 (j > 0) ? ", " : "",
                                 mongo_embedded_v1_match_details_elem_match_path_component(
                                     match_details, j));

                    if (bytes_written > bytes_left) {
                        break;
                    }

                    bytes_left -= bytes_written;
                    out_str += bytes_written;
                }

                if (strcmp(test->expectedElemMatchPath, elem_match_path_str) != 0) {
                    fprintf(stderr, "elemMatchPath did not match expected value\n");
                    goto fail;
                }
            } else if (test->expectedElemMatchPath) {
                fprintf(stderr, "Expected elemMatchPath but did not get one\n");
                goto fail;
            }
        } else if (test->expectedResult) {
            fprintf(stderr, "Unexpected non-matching document\n");
            goto fail;
        }

        printf("Test case %zu: %s\n", i, thumbs_up);
        mongo_embedded_v1_matcher_destroy(matcher);
        continue;

    fail:
        ++num_failures;
        printf("Test case %zu: %s\n", i, thumbs_down);
        mongo_embedded_v1_matcher_destroy(matcher);
    }

    mongo_embedded_v1_status_destroy(status);
    mongo_embedded_v1_match_details_destroy(match_details);

    return (num_failures == 0);
}

struct projection_test {
    const char* spec;
    const char* match_predicate;

    const char* document;

    const char* expected_result;
};

static struct projection_test projection_test_cases[] = {
    {"{a: 1}", NULL, "{_id: 1, a: 100, b: 200}", "{ \"_id\" : 1, \"a\" : 100 }"},
    {"{'a.$.c': 1}",
     "{'a.b': 1}",
     "{_id: 1, a: [{b: 2, c: 100}, {b: 1, c: 200}]}",
     "{ \"_id\" : 1, \"a\" : [ { \"b\" : 1, \"c\" : 200 } ] }"},
    {"{a: {$elemMatch: {b: 2}}}",
     NULL,
     "{a: [{b: 1, c: 1}, {b: 2, c: 2}]}",
     "{ \"a\" : [ { \"b\" : 2, \"c\" : 2 } ] }"},
    {"{a: {$slice: [1, 2]}}", NULL, "{a: [1, 2, 3, 4]}", "{ \"a\" : [ 2, 3 ] }"},
};

static size_t num_projection_test_cases =
    sizeof(projection_test_cases) / sizeof(projection_test_cases[0]);

static bool run_projection_tests(mongo_embedded_v1_lib* lib) {
    printf("Projection test cases\n");

    int num_failures = 0;
    mongo_embedded_v1_status* status = mongo_embedded_v1_status_create();

    for (size_t i = 0; i < num_projection_test_cases; ++i) {
        struct projection_test* test = &projection_test_cases[i];

        mongo_embedded_v1_matcher* matcher = NULL;
        mongo_embedded_v1_projection* projection = NULL;
        char* projection_result = NULL;
        const char* formatted_result = NULL;

        if (test->match_predicate) {
            matcher = mongo_embedded_v1_matcher_create(
                lib, parseJSONOrDie(test->match_predicate), status);
            if (!matcher) {
                fprintf(stderr,
                        "Failed to create matcher: %s\n",
                        mongo_embedded_v1_status_get_explanation(status));
                goto fail;
            }
        }

        projection =
            mongo_embedded_v1_projection_create(lib, parseJSONOrDie(test->spec), matcher, status);
        if (!projection) {
            fprintf(stderr,
                    "Failed to create projection: %s\n",
                    mongo_embedded_v1_status_get_explanation(status));
            goto fail;
        }

        projection_result = mongo_embedded_v1_projection_apply(
            projection, parseJSONOrDie(test->document), NULL, 0, status);
        if (!projection_result) {
            fprintf(stderr,
                    "Failed to apply projection: %s\n",
                    mongo_embedded_v1_status_get_explanation(status));
            goto fail;
        }

        formatted_result = formatAsJSONOrDie(projection_result);
        if (strcmp(test->expected_result, formatted_result) != 0) {
            fprintf(stderr, "Unexpected result from projection: %s\n", formatted_result);
            goto fail;
        }

        printf("Test case %zu: %s\n", i, thumbs_up);

        free(projection_result);
        mongo_embedded_v1_projection_destroy(projection);
        mongo_embedded_v1_matcher_destroy(matcher);

        continue;

    fail:
        ++num_failures;
        printf("Test case %zu: %s\n", i, thumbs_down);

        free(projection_result);
        mongo_embedded_v1_projection_destroy(projection);
        mongo_embedded_v1_matcher_destroy(matcher);
    }

    mongo_embedded_v1_status_destroy(status);

    return (num_failures == 0);
}

struct update_test {
    const char* update_expr;
    const char* array_filter_exprs;
    const char* match_predicate;

    const char* document;

    const char* expected_result;
    const char* expected_modified_paths;
};

static struct update_test update_test_cases[] = {
    {"{$set: {a: 2}}", NULL, NULL, "{a: 1}", "{ \"a\" : 2 }", "a"},
    {"{$set: {'a.1.b': 2}}",
     NULL,
     NULL,
     "{a: [{b: 1}]}",
     "{ \"a\" : [ { \"b\" : 1 }, { \"b\" : 2 } ] }",
     "a"},
    {"{$set: {'a.0.b': 2}}",
     NULL,
     NULL,
     "{a: [{b: 1}]}",
     "{ \"a\" : [ { \"b\" : 2 } ] }",
     "a, 0, b"},
    {"{$set: {'a.1.b': 2, c: 3}}",
     NULL,
     NULL,
     "{a: [{b: 1}]}",
     "{ \"a\" : [ { \"b\" : 1 }, { \"b\" : 2 } ], \"c\" : 3 }",
     "a;c"},
    {"{$set: {'a.$': 3}}", NULL, "{a: 2}", "{a: [1, 2]}", "{ \"a\" : [ 1, 3 ] }", "a, 1"},
    {"{$set: {'a.$.b': 3}}",
     NULL,
     "{'a.b': 2}",
     "{a: [{b: 1}, {b: 2}]}",
     "{ \"a\" : [ { \"b\" : 1 }, { \"b\" : 3 } ] }",
     "a, 1, b"},
    {"{$set: {'a.$[i]': 3}}", "[{i: 2}]", NULL, "{a: [1, 2]}", "{ \"a\" : [ 1, 3 ] }", "a, 1"},
    {"{$set: {'a.$[i].b': 3}}",
     "[{'i.b': 2}]",
     NULL,
     "{a: [{b: 1}, {b: 2}]}",
     "{ \"a\" : [ { \"b\" : 1 }, { \"b\" : 3 } ] }",
     "a, 1, b"},
};

static size_t num_update_test_cases = sizeof(update_test_cases) / sizeof(update_test_cases[0]);

static const char* format_update_details(mongo_embedded_v1_update_details* update_details) {
    static char output[4096];
    char* output_tail = output;

    output[0] = '\0';

    size_t num_paths = mongo_embedded_v1_update_details_num_modified_paths(update_details);
    for (size_t i = 0; i < num_paths; ++i) {
        size_t path_length = mongo_embedded_v1_update_details_path_length(update_details, i);
        for (size_t j = 0; j < path_length; ++j) {
            const char* component =
                mongo_embedded_v1_update_details_path_component(update_details, i, j);
            const char* separator =
                (j == (path_length - 1)) ? (i == (num_paths - 1)) ? "" : ";" : ", ";
            output_tail += snprintf(
                output_tail, output + sizeof(output) - output_tail, "%s%s", component, separator);

            if (output_tail >= output + sizeof(output)) {
                return output;
            }
        }
    }

    return output;
}

static bool run_update_tests(mongo_embedded_v1_lib* lib) {
    printf("Update test cases\n");

    int num_failures = 0;
    mongo_embedded_v1_status* status = mongo_embedded_v1_status_create();
    mongo_embedded_v1_update_details* update_details = mongo_embedded_v1_update_details_create();

    for (size_t i = 0; i < num_update_test_cases; ++i) {
        struct update_test* test = &update_test_cases[i];

        mongo_embedded_v1_matcher* matcher = NULL;
        mongo_embedded_v1_update* update = NULL;
        char* update_result = NULL;
        const char* formatted_result;

        if (test->match_predicate) {
            matcher = mongo_embedded_v1_matcher_create(
                lib, parseJSONOrDie(test->match_predicate), status);
            if (!matcher) {
                fprintf(stderr,
                        "Failed to create matcher: %s\n",
                        mongo_embedded_v1_status_get_explanation(status));
                goto fail;
            }
        }

        char update_expr_buf[2048];
        char array_filters_buf[2048];
        update = mongo_embedded_v1_update_create(
            lib,
            parseJSONToBufferOrDie(test->update_expr, update_expr_buf, sizeof(update_expr_buf)),
            test->array_filter_exprs ? parseJSONToBufferOrDie(test->array_filter_exprs,
                                                              array_filters_buf,
                                                              sizeof(array_filters_buf))
                                     : NULL,
            matcher,
            status);

        if (!update) {
            fprintf(stderr,
                    "Failed to create update: %s\n",
                    mongo_embedded_v1_status_get_explanation(status));
            goto fail;
        }

        update_result = mongo_embedded_v1_update_apply(
            update, parseJSONOrDie(test->document), NULL, 0, update_details, status);
        if (!update_result) {
            fprintf(stderr,
                    "Failed to apply update: %s\n",
                    mongo_embedded_v1_status_get_explanation(status));
            goto fail;
        }

        formatted_result = formatAsJSONOrDie(update_result);
        if (strcmp(test->expected_result, formatted_result) != 0) {
            fprintf(stderr, "Unexpected result from update: %s\n", formatted_result);
            goto fail;
        }

        formatted_result = format_update_details(update_details);
        if (strcmp(test->expected_modified_paths, formatted_result) != 0) {
            fprintf(stderr, "Unexpected modfied paths: %s\n", formatted_result);
            goto fail;
        }

        printf("Test case %zu: %s\n", i, thumbs_up);

        mongo_embedded_v1_update_destroy(update);
        mongo_embedded_v1_matcher_destroy(matcher);

        continue;

    fail:
        ++num_failures;
        printf("Test case %zu: %s\n", i, thumbs_down);

        mongo_embedded_v1_update_destroy(update);
        mongo_embedded_v1_matcher_destroy(matcher);
    }

    mongo_embedded_v1_status_destroy(status);
    mongo_embedded_v1_update_details_destroy(update_details);

    return (num_failures == 0);
}

int main(const int argc, const char* const* const argv) {
    mongo_embedded_v1_init_params params;
    params.yaml_config = NULL;
    params.log_flags = MONGO_EMBEDDED_V1_LOG_NONE;
    params.log_user_data = NULL;
    mongo_embedded_v1_lib* lib = mongo_embedded_v1_lib_init(&params, NULL);

    bool all_tests_passed = true;
    all_tests_passed &= run_match_tests(lib);
    all_tests_passed &= run_projection_tests(lib);
    all_tests_passed &= run_update_tests(lib);

    exit(all_tests_passed ? 0 : 1);
}
