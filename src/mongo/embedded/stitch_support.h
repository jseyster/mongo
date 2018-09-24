/*-
 *    Copyright (C) 2018 MongoDB Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the GNU Affero General Public License in all respects
 *    for all of the code used other than as permitted herein. If you modify
 *    file(s) with this exception, you may extend this exception to your
 *    version of the file(s), but you are not obligated to do so. If you do not
 *    wish to do so, delete this exception statement from your version. If you
 *    delete this exception statement from all source files in the program,
 *    then also delete it in the license file.
 */
#ifndef HEADERUUID_5AF7DBB0_F911_4238_90CE_1145ED323D3B_DEFINED
#define HEADERUUID_5AF7DBB0_F911_4238_90CE_1145ED323D3B_DEFINED

#include <stddef.h>
#include <stdint.h>

#pragma push_macro("MONGO_API_CALL")
#undef MONGO_API_CALL

#pragma push_macro("MONGO_API_IMPORT")
#undef MONGO_API_IMPORT

#pragma push_macro("MONGO_API_EXPORT")
#undef MONGO_API_EXPORT

#pragma push_macro("MONGO_EMBEDDED_CAPI_API")
#undef MONGO_EMBEDDED_CAPI_API

#if defined(_WIN32)
#define MONGO_API_CALL __cdecl
#define MONGO_API_IMPORT __declspec(dllimport)
#define MONGO_API_EXPORT __declspec(dllexport)
#else
#define MONGO_API_CALL
#define MONGO_API_IMPORT __attribute__((visibility("default")))
#define MONGO_API_EXPORT __attribute__((used, visibility("default")))
#endif

#if defined(MONGO_EMBEDDED_CAPI_STATIC)
#define MONGO_EMBEDDED_CAPI_API
#else
#if defined(MONGO_EMBEDDED_CAPI_COMPILING)
#define MONGO_EMBEDDED_CAPI_API MONGO_API_EXPORT
#else
#define MONGO_EMBEDDED_CAPI_API MONGO_API_IMPORT
#endif
#endif

#ifdef _DOXYGEN
/**
 * Stitch support POC.
 */
namespace mongo {
namespace embedded {
// Doxygen requires a namespace when processing global scope functions, in order to generate
// documentation. We also use it as a hook to provide library-wide documentation.
#endif

#ifdef __cplusplus

extern "C" {
#endif

typedef struct mongo_embedded_v1_status mongo_embedded_v1_status;

/**
 * The embedded status object is copied from the C API. Clients can pass the same status object to
 * each function that takes a status object as one of its parameters, checking each time if the
 * function failed with an error status (using mongo_embedded_v1_status_get_error()).
 *
 * Clients can also pass NULL, but they will not be able to determine the cause of a failure.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_status* MONGO_API_CALL
mongo_embedded_v1_status_create(void);

MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_status_destroy(mongo_embedded_v1_status* status);

typedef enum {
    MONGO_EMBEDDED_V1_ERROR_IN_REPORTING_ERROR = -2,
    MONGO_EMBEDDED_V1_ERROR_UNKNOWN = -1,

    MONGO_EMBEDDED_V1_SUCCESS = 0,

    MONGO_EMBEDDED_V1_ERROR_ENOMEM = 1,
    MONGO_EMBEDDED_V1_ERROR_EXCEPTION = 2,
    MONGO_EMBEDDED_V1_ERROR_LIBRARY_ALREADY_INITIALIZED = 3,
    MONGO_EMBEDDED_V1_ERROR_LIBRARY_NOT_INITIALIZED = 4,
    MONGO_EMBEDDED_V1_ERROR_INVALID_LIB_HANDLE = 5,
    MONGO_EMBEDDED_V1_ERROR_DB_INITIALIZATION_FAILED = 6,
    MONGO_EMBEDDED_V1_ERROR_INVALID_DB_HANDLE = 7,
    MONGO_EMBEDDED_V1_ERROR_HAS_DB_HANDLES_OPEN = 8,
    MONGO_EMBEDDED_V1_ERROR_DB_MAX_OPEN = 9,
    MONGO_EMBEDDED_V1_ERROR_DB_CLIENTS_OPEN = 10,
    MONGO_EMBEDDED_V1_ERROR_INVALID_CLIENT_HANDLE = 11,
    MONGO_EMBEDDED_V1_ERROR_REENTRANCY_NOT_ALLOWED = 12,
} mongo_embedded_v1_error;

MONGO_EMBEDDED_CAPI_API int MONGO_API_CALL
mongo_embedded_v1_status_get_error(const mongo_embedded_v1_status* status);

MONGO_EMBEDDED_CAPI_API const char* MONGO_API_CALL
mongo_embedded_v1_status_get_explanation(const mongo_embedded_v1_status* status);

MONGO_EMBEDDED_CAPI_API int MONGO_API_CALL
mongo_embedded_v1_status_get_code(const mongo_embedded_v1_status* status);

typedef struct mongo_embedded_v1_match_details mongo_embedded_v1_match_details;

/**
 * Create a "match details" object to pass to mongo_embedded_v1_check_match(), which will populate
 * the match details with an "elem_path" if the match traverses an array element.
 *
 * Clients can resuse the same match details object for multiple calls to
 * mongo_embedded_v1_check_match().
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_match_details* MONGO_API_CALL
mongo_embedded_v1_match_details_create(void);

MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_match_details_destroy(mongo_embedded_v1_match_details* match_details);

/**
 * When the matcher performs an implicit array traversal to find the matching element, the
 * 'match_details' will include an "elem_match_path" value, which is the path to the array that was
 * traversed. Callers should always check that this function returns true before calling
 * mongo_embedded_v1_match_details_elem_match_path_length() or
 * mongo_embedded_v1_match_details_elem_match_path_component().
 *
 * If a match traverses two or more arrays, the "elem_match_path" references the first array along
 * the path.
 */
MONGO_EMBEDDED_CAPI_API bool MONGO_API_CALL
mongo_embedded_v1_match_details_has_elem_match_path(mongo_embedded_v1_match_details* match_details);

/**
 * The length of the "elem_match_path" iff it exists. Always call this function to ensure an index
 * is in bounds before calling mongo_embedded_v1_match_details_elem_match_path_component.
 */
MONGO_EMBEDDED_CAPI_API size_t MONGO_API_CALL
mongo_embedded_v1_match_details_elem_match_path_length(
    mongo_embedded_v1_match_details* match_details);

/**
 * Return a component from the "elem_match_path" from a given 'match_details' value. As an example,
 * the path 'a.b.c' has three components: ['a', 'b', 'c'].
 *
 * The "elem_match_path" does not distinguish a path component that represents an array index from a
 * path component that represents a numerical field name (e.g., path 'a.0.b' in {a: {'0': {b: 1}} vs
 * {a: [{b: 1}]}). If we decide to add support for that distinction, I suggest two additional out
 * parameters to indicate an array index parameter and return its numerical value.
 */
MONGO_EMBEDDED_CAPI_API const char* MONGO_API_CALL
mongo_embedded_v1_match_details_elem_match_path_component(
    mongo_embedded_v1_match_details* match_details, size_t index /*,
    bool* out_is_array_index,
    size_t* out_component_as_index*/);

typedef struct mongo_embedded_v1_lib mongo_embedded_v1_lib;
typedef struct mongo_embedded_v1_init_params mongo_embedded_v1_init_params;
typedef struct mongo_embedded_v1_matcher mongo_embedded_v1_matcher;

/**
 * A client program should call this library initialization function exactly once.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_lib* MONGO_API_CALL mongo_embedded_v1_lib_init(
    const mongo_embedded_v1_init_params* params, mongo_embedded_v1_status* status);

/**
 * A matcher object is used to determine if a BSON document matches a predicate. The predicate
 * itself is also represented as a BSON object, which is passed in the 'patternBSON' argument.
 *
 * This function will fail if the predicate is invalid, returning NULL and populating 'status' with
 * information about the error.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_matcher* MONGO_API_CALL mongo_embedded_v1_matcher_create(
    mongo_embedded_v1_lib* lib, const char* patternBSON, mongo_embedded_v1_status* status);

MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_matcher_destroy(mongo_embedded_v1_matcher* const matcher);

/**
 * Check if the 'documentBSON' input matches the predicate represented by the 'matcher' object and
 * populate 'matchDetails' (if it is not NULL) with information about implicit array traversal.
 *
 * Note that callers should always check for an error status in the 'status' object, because a false
 * return value can indicate that the document did not match or that an error occurred during
 * matching.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_error MONGO_API_CALL
mongo_embedded_v1_check_match(mongo_embedded_v1_matcher* matcher,
                              const char* documentBSON,
                              bool* isMatch,
                              mongo_embedded_v1_match_details* matchDetails,
                              mongo_embedded_v1_status* status);

/**
 * Valid bits for the log_flags bitfield in mongo_embedded_v1_init_params.
 */
typedef enum {
    /** Placeholder for no logging */
    MONGO_EMBEDDED_V1_LOG_NONE = 0,

    /** Logs to stdout */
    MONGO_EMBEDDED_V1_LOG_STDOUT = 1,

    /** Logs to stderr (not supported yet) */
    // MONGO_EMBEDDED_V1_LOG_STDERR = 2,

    /** Logs via log callback that must be provided when this bit is set. (not supported) */
    // MONGO_EMBEDDED_V1_LOG_CALLBACK = 4
} mongo_embedded_v1_log_flags;

// See the documentation of this object on the comments above its forward declaration
struct mongo_embedded_v1_init_params {
    /**
     * Optional null-terminated YAML formatted MongoDB configuration string.
     * See documentation for valid options.
     */
    const char* yaml_config;

    /**
     * Bitfield of log destinations, accepts values from mongo_embedded_v1_log_flags.
     * Default is stdout.
     */
    uint64_t log_flags;

    /**
     * Optional user data to be returned in the log callback.
     */
    void* log_user_data;
};

#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef _DOXYGEN
}  // namespace embedded
}  // namespace mongo
#endif

#undef MONGO_EMBEDDED_CAPI_API
#pragma pop_macro("MONGO_EMBEDDED_CAPI_API")

#undef MONGO_API_EXPORT
#pragma push_macro("MONGO_API_EXPORT")

#undef MONGO_API_IMPORT
#pragma push_macro("MONGO_API_IMPORT")

#undef MONGO_API_CALL
#pragma pop_macro("MONGO_API_CALL")

#endif  // HEADERUUID_5AF7DBB0_F911_4238_90CE_1145ED323D3B_DEFINED
