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

typedef struct mongo_embedded_v1_update_details mongo_embedded_v1_update_details;

/**
 * Create an "update details" object to pass to mongo_embedded_v1_update_apply(), which will
 * populate the update details with a list of paths modified by the update.
 *
 * Clients can reuse the same update details object for multiple calls to
 * mongo_embedded_v1_update_apply().
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_update_details* MONGO_API_CALL
mongo_embedded_v1_update_details_create(void);

MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_update_details_destroy(mongo_embedded_v1_update_details* update_details);

// TODO: This should be on the update, not the UpdateDetails
MONGO_EMBEDDED_CAPI_API bool MONGO_API_CALL
mongo_embedded_v1_update_details_is_replacement(mongo_embedded_v1_update_details* update_details);

/**
 * The number of modified paths in an update details object. Always call this function to ensure an
 * index is in bounds before calling mongo_embedded_v1_update_details_path_length() or
 * mongo_embedded_v1_update_details_path_component().
 */
MONGO_EMBEDDED_CAPI_API size_t MONGO_API_CALL mongo_embedded_v1_update_details_num_modified_paths(
    mongo_embedded_v1_update_details* update_details);

/**
 * The number of path components in the modified path at the given index. Always call this function
 * to ensure an index is in bounds before calling mongo_embedded_v1_update_details_path_component().
 */
MONGO_EMBEDDED_CAPI_API size_t MONGO_API_CALL mongo_embedded_v1_update_details_path_length(
    mongo_embedded_v1_update_details* update_details, size_t path_index);

/**
 * Return a component from one of the modified paths in the update details object. The above note
 *  about distinguishing field names from array indexes in the documentation of
 * mongo_embedded_v1_match_details_elem_match_path_component() also applies here.
 */
MONGO_EMBEDDED_CAPI_API const char* MONGO_API_CALL mongo_embedded_v1_update_details_path_component(
    mongo_embedded_v1_update_details* update_details, size_t path_index, size_t component_index);

typedef struct mongo_embedded_v1_lib mongo_embedded_v1_lib;
typedef struct mongo_embedded_v1_init_params mongo_embedded_v1_init_params;
typedef struct mongo_embedded_v1_matcher mongo_embedded_v1_matcher;
typedef struct mongo_embedded_v1_projection mongo_embedded_v1_projection;
typedef struct mongo_embedded_v1_update mongo_embedded_v1_update;

/**
 * A client program should call this library initialization function exactly once.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_lib* MONGO_API_CALL mongo_embedded_v1_lib_init(
    const mongo_embedded_v1_init_params* params, mongo_embedded_v1_status* status);

typedef struct mongo_embedded_v1_collator mongo_embedded_v1_collator;

// TODO: Collator comments
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_collator* MONGO_API_CALL
mongo_embedded_v1_collator_create(mongo_embedded_v1_lib* lib,
                                  const char* collationBSON,
                                  mongo_embedded_v1_status* const status);

MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_collator_destroy(mongo_embedded_v1_collator* collator);

/**
 * A matcher object is used to determine if a BSON document matches a predicate. The predicate
 * itself is also represented as a BSON object, which is passed in the 'patternBSON' argument.
 *
 * This function will fail if the predicate is invalid, returning NULL and populating 'status' with
 * information about the error.
 *
 * The matcher can optionally use a collator. The newly created matcher does _not_ take ownership of
 * its 'collator' object. The client is responsible for ensuring that the collator continues to
 * exist for the lifetime of the matcher and for ultimately destroying both the collator and the
 * matcher. Multiple matcher, projection, and update objects can share the same collation object.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_matcher* MONGO_API_CALL
mongo_embedded_v1_matcher_create(mongo_embedded_v1_lib* lib,
                                 const char* patternBSON,
                                 mongo_embedded_v1_collator* collator,
                                 mongo_embedded_v1_status* status);

MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_matcher_destroy(mongo_embedded_v1_matcher* const matcher);

/**
 * Check if the 'documentBSON' input matches the predicate represented by the 'matcher' object and
 * populate 'matchDetails' (if it is not NULL) with information about implicit array traversal.
 *
 * When the check is successful, this function returns MONGO_EMBEDDED_V1_SUCCESS, sets 'isMatch' to
 * indicate whether the document matched, and populates 'matchDetails' (when it is not NULL).
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_error MONGO_API_CALL
mongo_embedded_v1_check_match(mongo_embedded_v1_matcher* matcher,
                              const char* documentBSON,
                              bool* isMatch,
                              mongo_embedded_v1_match_details* matchDetails,
                              mongo_embedded_v1_status* status);

/**
 * A projection object is used to apply a projection to a BSON document. The projection
 * specification is also represented as a BSON document, which is passed in the 'specBSON' argument.
 * The syntax used for projection is the same as a MongoDB "find" command (i.e., not an aggregation
 * $project stage).
 *
 * If the projection specification include's a positional ($) operator, then the caller must pass a
 * mongo_embedded_v1_matcher, which is used to determine which array element matches the positional.
 * The 'matcher' argument is not used when the specification has no positional operator, and it can
 * be NULL.
 *
 * The caller can optionally provide a collator, which is used when evaluating $elemMatch operators.
 * When 'collator' is NULL, $elemMatch will use the default collation, even if 'matcher' has a
 * collator object. Multiple matcher, projection, and update objects can share the same collation
 * object.
 *
 * The newly created projection object does _not_ take ownership of its 'matcher' or 'collator'
 * objects. The client is responsible for ensuring that the matcher and collator continue to exist
 * for the lifetime of the projection and for ultimately destroying all three of the projection,
 * matcher and collator.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_projection* MONGO_API_CALL
mongo_embedded_v1_projection_create(mongo_embedded_v1_lib* lib,
                                    const char* specBSON,
                                    mongo_embedded_v1_matcher* matcher,
                                    mongo_embedded_v1_collator* collator,
                                    mongo_embedded_v1_status* status);

MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_projection_destroy(mongo_embedded_v1_projection* const projection);

/**
 * Apply a projection to an input document, writing the resulting BSON to the 'output' buffer.
 * Returns a pointer to the output buffer (which is the same as the value of 'output' when it is not
 * NULL) on success or NULL on error (including when 'output_size' is too small to fit the
 * projection result).
 *
 * The caller may pass NULL for the 'output' argument, in which case this function allocates a
 * buffer of exactly the right size for the resulting document (ignoring the value of
 * 'output_size'). The caller is responsible for destroying the resulting buffer with free().
 *
 * If the projection includes a positional ($) operator, the caller should verify before applying it
 * that the associated matcher matches the input document. A non-matching input document will
 * trigger an assertion failure.
 */
MONGO_EMBEDDED_CAPI_API char* MONGO_API_CALL
mongo_embedded_v1_projection_apply(mongo_embedded_v1_projection* const projection,
                                   const char* documentBSON,
                                   char* output,
                                   size_t output_size,
                                   mongo_embedded_v1_status* status);

/**
 * An update object is used to apply an update to a BSON document, which may modify particular
 * fields (e.g.: {$set: {a: 1}}) or replace the entire document with a new one.
 *
 * If the update expression includes a positional ($) operator, then the caller must pass a
 * mongo_embedded_v1_matcher, which is used to determine which array element matches the positional.
 * The 'matcher' argument is not used when the update expression has no positional operator, and it
 * can be NULL.
 *
 * The caller can optionally provide a collator, which is used when evaluating arrayFilters match
 * expressions. When 'collator' is NULL, arrayFilters will use the default collation, even if
 * 'matcher' has a collator object. Multiple matcher, projection, and update objects can share the
 * same collation object.
 *
 * The newly created update object does _not_ take ownership of its 'matcher' or 'collators'
 * objects. The client is responsible for ensuring that the matcher and collator continue to exist
 * for the lifetime of the update and for ultimately destroying all three of the update, matcher,
 * and collator.
 */
MONGO_EMBEDDED_CAPI_API mongo_embedded_v1_update* MONGO_API_CALL
mongo_embedded_v1_update_create(mongo_embedded_v1_lib* lib,
                                const char* updateBSON,
                                const char* arrayFiltersBSON,
                                mongo_embedded_v1_matcher* matcher,
                                mongo_embedded_v1_collator* collator,
                                mongo_embedded_v1_status* status);


MONGO_EMBEDDED_CAPI_API void MONGO_API_CALL
mongo_embedded_v1_update_destroy(mongo_embedded_v1_update* const update);

/**
 * Apply an update to an input document, writing the resulting BSON to the 'output' buffer. Returns
 * a pointer to the output buffer (which is the same as the value of 'output' when it is not NULL)
 * on success or NULL on error (including whne 'output_size' is too small to fit the update result).
 *
 * The caller may pass NULL for the 'output' argument, in which case this function allocates a
 * buffer of exactly the right size for the resulting document (ignoring the value of
 * 'output_size'). The caller is responsible for destroying the result buffer with free().
 *
 * If the update includes a positional ($) operator, the caller should verify before applying it
 * that the associated matcher matches the input document. A non-matching input document will
 * trigger an assertion failure.
 */
MONGO_EMBEDDED_CAPI_API char* MONGO_API_CALL
mongo_embedded_v1_update_apply(mongo_embedded_v1_update* const update,
                               const char* documentBSON,
                               char* output,
                               size_t output_size,
                               mongo_embedded_v1_update_details* update_details,
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
