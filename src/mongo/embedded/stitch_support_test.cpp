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

/**
 * This JSON parsing function is intended for testing, not for parsing user input. It aborts if it
 * fails to parse its input or if there is not enough buffer space for the output.
 *
 * Returns 'outBuffer' as a convenience.
 */
static const char* parseJSONToBufferOrDie(char* outBuffer,
                                          size_t bufferSize,
                                          const char* jsonString) {
    int parsedLen = 0;

    // This may throw an exception, which will be left uncaught, also aborting the program.
    auto bson = mongo::fromjson(jsonString, &parsedLen);

    if (parsedLen != (int)strlen(jsonString) || bson.objsize() > (int)bufferSize) {
        fprintf(stderr, "FATAL -- Failed to parse: \"%s\"\n", jsonString);
        abort();
    }

    memcpy(outBuffer, bson.objdata(), bson.objsize());

    return outBuffer;
}

struct match_test {
    const char* predicate;
    const char* document;

    bool expectedResult;
    const char* expectedElemMatchPath;
};

static struct match_test test_cases[] = {
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

static size_t num_test_cases = sizeof(test_cases) / sizeof(test_cases[0]);

static const char thumbs_up[] = {static_cast<char>(0xF0),
                                 static_cast<char>(0x9F),
                                 static_cast<char>(0x91),
                                 static_cast<char>(0x8D),
                                 0x00};

int main(const int argc, const char* const* const argv) {
    mongo_embedded_v1_init_params params;
    params.yaml_config = NULL;
    params.log_flags = MONGO_EMBEDDED_V1_LOG_NONE;
    params.log_user_data = NULL;
    mongo_embedded_v1_lib* lib = mongo_embedded_v1_lib_init(&params, NULL);

    mongo_embedded_v1_status* status = mongo_embedded_v1_status_create();
    mongo_embedded_v1_match_details* match_details = mongo_embedded_v1_match_details_create();

    bool isMatch = false;
    char buffer[4096];

    for (size_t test_index = 0; test_index < num_test_cases; ++test_index) {
        const char* match_str = test_cases[test_index].predicate;
        mongo_embedded_v1_matcher* matcher = mongo_embedded_v1_matcher_create(
            lib, parseJSONToBufferOrDie(buffer, sizeof(buffer), match_str), status);

        if (MONGO_EMBEDDED_V1_SUCCESS != mongo_embedded_v1_status_get_error(status)) {
            fprintf(stderr,
                    "Failed to create matcher: %s\n",
                    mongo_embedded_v1_status_get_explanation(status));
            exit(1);
        }

        const char* doc_str = test_cases[test_index].document;
        if (MONGO_EMBEDDED_V1_SUCCESS !=
            mongo_embedded_v1_check_match(matcher,
                                          parseJSONToBufferOrDie(buffer, sizeof(buffer), doc_str),
                                          &isMatch,
                                          match_details,
                                          status)) {
            fprintf(stderr,
                    "Test case %zu: Failed to check match: %s\n",
                    test_index,
                    mongo_embedded_v1_status_get_explanation(status));
            exit(1);
        }

        if (isMatch) {
            if (!test_cases[test_index].expectedResult) {
                fprintf(stderr, "Test case %zu: unexpected match\n", test_index);
                exit(1);
            }

            if (mongo_embedded_v1_match_details_has_elem_match_path(match_details)) {
                if (!test_cases[test_index].expectedElemMatchPath) {
                    fprintf(stderr, "Test case %zu: unexpected elemMatchPath\n", test_index);
                    exit(1);
                }

                // Dump the elemMatchPath to a string.
                char elem_match_path_str[1024];
                int bytes_left = sizeof(elem_match_path_str);
                char* out_str = elem_match_path_str;

                int path_length =
                    mongo_embedded_v1_match_details_elem_match_path_length(match_details);
                for (int i = 0; i < path_length; ++i) {
                    int bytes_written =
                        snprintf(out_str,
                                 bytes_left,
                                 "%s%s",
                                 (i > 0) ? ", " : "",
                                 mongo_embedded_v1_match_details_elem_match_path_component(
                                     match_details, i));

                    if (bytes_written > bytes_left) {
                        break;
                    }

                    bytes_left -= bytes_written;
                    out_str += bytes_written;
                }

                if (strcmp(test_cases[test_index].expectedElemMatchPath, elem_match_path_str) !=
                    0) {
                    fprintf(stderr,
                            "Test case %zu: elemMatchPath did not match expected value\n",
                            test_index);
                    exit(1);
                }
            } else if (test_cases[test_index].expectedElemMatchPath) {
                fprintf(stderr,
                        "Test case %zu: expected elemMatchPath but did not get one\n",
                        test_index);
                exit(1);
            }
        } else if (test_cases[test_index].expectedResult) {
            fprintf(stderr, "Test case %zu: unexpected non-matching document\n", test_index);
            exit(1);
        }

        mongo_embedded_v1_matcher_destroy(matcher);

        printf("Test case %zu: %s\n", test_index, thumbs_up);
    }

    mongo_embedded_v1_status_destroy(status);
    mongo_embedded_v1_match_details_destroy(match_details);

    printf("All tests passed: %s\n", thumbs_up);

    exit(0);
}
