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
 *    must comply with the GNU Affero General Public License in all respects
 *    for all of the code used other than as permitted herein. If you modify
 *    file(s) with this exception, you may extend this exception to your
 *    version of the file(s), but you are not obligated to do so. If you do not
 *    wish to do so, delete this exception statement from your version. If you
 *    delete this exception statement from all source files in the program,
 *    then also delete it in the license file.
 */

#include "mongo/platform/basic.h"

#include "mongo/embedded/stitch_support.h"

#include <iostream>

#include "mongo/bson/bsonobj.h"
#include "mongo/db/client.h"
#include "mongo/db/matcher/match_details.h"
#include "mongo/db/matcher/matcher.h"
#include "mongo/db/pipeline/expression_context.h"
#include "mongo/logger/log_manager.h"
#include "mongo/logger/logger.h"
#include "mongo/transport/transport_layer_mock.h"

#if defined(_WIN32)
#define MONGO_API_CALL __cdecl
#else
#define MONGO_API_CALL
#endif

struct mongo_embedded_v1_status {
    mongo_embedded_v1_status() noexcept = default;
    mongo_embedded_v1_status(const mongo_embedded_v1_error e, const int ec, std::string w)
        : error(e), exception_code(ec), what(std::move(w)) {}

    void clean() noexcept {
        error = MONGO_EMBEDDED_V1_SUCCESS;
    }

    mongo_embedded_v1_error error = MONGO_EMBEDDED_V1_SUCCESS;
    int exception_code = 0;
    std::string what;
};

namespace {
mongo::ServiceContext* initialize(const char* yaml_config) {
    srand(static_cast<unsigned>(mongo::curTimeMicros64()));

    // yaml_config is passed to the options parser through the argc/argv interface that already
    // existed. If it is nullptr then use 0 count which will be interpreted as empty string.
    const char* argv[2] = {yaml_config, nullptr};

    mongo::Status status = mongo::runGlobalInitializers(yaml_config ? 1 : 0, argv, nullptr);
    uassertStatusOKWithContext(status, "Global initilization failed");
    mongo::setGlobalServiceContext(mongo::ServiceContext::make());

    return mongo::getGlobalServiceContext();
}
}  // namespace

namespace mongo {
namespace {
struct ServiceContextDestructor {
    void operator()(mongo::ServiceContext* const serviceContext) const noexcept {
        //::mongo::embedded::shutdown(serviceContext);
    }
};

using EmbeddedServiceContextPtr = std::unique_ptr<mongo::ServiceContext, ServiceContextDestructor>;
}  // namespace
}  // namespace mongo

namespace mongo {
namespace {
class MobileException : public std::exception {
public:
    explicit MobileException(const mongo_embedded_v1_error code, std::string m)
        : _mesg(std::move(m)), _code(code) {}

    mongo_embedded_v1_error mobileCode() const noexcept {
        return this->_code;
    }

    const char* what() const noexcept final {
        return this->_mesg.c_str();
    }

private:
    std::string _mesg;
    mongo_embedded_v1_error _code;
};

mongo_embedded_v1_status translateException() try { throw; } catch (const MobileException& ex) {
    return {ex.mobileCode(), mongo::ErrorCodes::InternalError, ex.what()};
} catch (const ExceptionFor<ErrorCodes::ReentrancyNotAllowed>& ex) {
    return {MONGO_EMBEDDED_V1_ERROR_REENTRANCY_NOT_ALLOWED, ex.code(), ex.what()};
} catch (const DBException& ex) {
    return {MONGO_EMBEDDED_V1_ERROR_EXCEPTION, ex.code(), ex.what()};
} catch (const std::bad_alloc& ex) {
    return {MONGO_EMBEDDED_V1_ERROR_ENOMEM, mongo::ErrorCodes::InternalError, ex.what()};
} catch (const std::exception& ex) {
    return {MONGO_EMBEDDED_V1_ERROR_UNKNOWN, mongo::ErrorCodes::InternalError, ex.what()};
} catch (...) {
    return {MONGO_EMBEDDED_V1_ERROR_UNKNOWN,
            mongo::ErrorCodes::InternalError,
            "Unknown error encountered in performing requested mongo_embedded_v1 operation"};
}

std::nullptr_t handleException(mongo_embedded_v1_status& status) noexcept {
    try {
        status = translateException();
    } catch (...) {
        status.error = MONGO_EMBEDDED_V1_ERROR_IN_REPORTING_ERROR;

        try {
            status.exception_code = -1;

            status.what.clear();

            // Expected to be small enough to fit in the capacity that string always has.
            const char severeErrorMessage[] = "Severe Error";

            if (status.what.capacity() > sizeof(severeErrorMessage)) {
                status.what = severeErrorMessage;
            }
        } catch (...) /* Ignore any errors at this point. */
        {
        }
    }
    return nullptr;
}

}  // namespace
}  // namespace mongo

struct mongo_embedded_v1_lib {
    ~mongo_embedded_v1_lib() {
        invariant(this->databaseCount.load() == 0);

        if (this->logCallbackHandle) {
            using mongo::logger::globalLogDomain;
            globalLogDomain()->detachAppender(this->logCallbackHandle);
            this->logCallbackHandle.reset();
        }
    }

    mongo_embedded_v1_lib(const mongo_embedded_v1_lib&) = delete;
    void operator=(const mongo_embedded_v1_lib) = delete;

    mongo_embedded_v1_lib(const char* const yaml_config)
        : serviceContext(initialize(yaml_config)),
          transportLayer(std::make_unique<mongo::transport::TransportLayerMock>()){};

    mongo::AtomicWord<int> databaseCount;

    mongo::logger::ComponentMessageLogDomain::AppenderHandle logCallbackHandle;

    mongo::EmbeddedServiceContextPtr serviceContext;
    std::unique_ptr<mongo::transport::TransportLayerMock> transportLayer;
};

struct mongo_embedded_v1_matcher {
    mongo_embedded_v1_matcher(mongo::ServiceContext::UniqueClient client,
                              const mongo::BSONObj& pattern)
        : client(std::move(client)),
          opCtx(this->client->makeOperationContext()),
          matcher(pattern, new mongo::ExpressionContext(opCtx.get(), nullptr)){};

    mongo::ServiceContext::UniqueClient client;
    mongo::ServiceContext::UniqueOperationContext opCtx;
    mongo::Matcher matcher;
};

struct mongo_embedded_v1_match_details {
    mongo::MatchDetails matchDetails;

    mongo_embedded_v1_match_details() : matchDetails() {
        matchDetails.requestElemMatchKey();
    }
};

namespace mongo {
namespace {

std::unique_ptr<mongo_embedded_v1_lib> library;

class ReentrancyGuard {
private:
    thread_local static bool inLibrary;

public:
    explicit ReentrancyGuard() {
        uassert(ErrorCodes::ReentrancyNotAllowed,
                str::stream() << "Reentry into mongo_embedded_v1 library is not allowed",
                !inLibrary);
        inLibrary = true;
    }

    ~ReentrancyGuard() {
        inLibrary = false;
    }

    ReentrancyGuard(ReentrancyGuard const&) = delete;
    ReentrancyGuard& operator=(ReentrancyGuard const&) = delete;
};

thread_local bool ReentrancyGuard::inLibrary = false;

mongo_embedded_v1_lib* stitch_support_lib_init(mongo_embedded_v1_init_params const* params,
                                               mongo_embedded_v1_status& status) try {
    if (library) {
        throw MobileException{
            MONGO_EMBEDDED_V1_ERROR_LIBRARY_ALREADY_INITIALIZED,
            "Cannot initialize the MongoDB Embedded Library when it is already initialized."};
    }

    auto lib = std::make_unique<mongo_embedded_v1_lib>(params->yaml_config);

    // TODO(adam.martin): Fold all of this log initialization into the ctor of lib.
    if (params) {
        using logger::globalLogManager;
        // The standard console log appender may or may not be installed here, depending if this is
        // the first time we initialize the library or not. Make sure we handle both cases.
        if (params->log_flags & MONGO_EMBEDDED_V1_LOG_STDOUT) {
            if (!globalLogManager()->isDefaultConsoleAppenderAttached())
                globalLogManager()->reattachDefaultConsoleAppender();
        } else {
            if (globalLogManager()->isDefaultConsoleAppenderAttached())
                globalLogManager()->detachDefaultConsoleAppender();
        }
    }

    library = std::move(lib);

    return library.get();
} catch (...) {
    // Make sure that no actual logger is attached if library cannot be initialized.  Also prevent
    // exception leaking failures here.
    []() noexcept {
        using logger::globalLogManager;
        if (globalLogManager()->isDefaultConsoleAppenderAttached())
            globalLogManager()->detachDefaultConsoleAppender();
    }
    ();
    throw;
}

mongo_embedded_v1_matcher* matcher_new(mongo_embedded_v1_lib* const lib,
                                       BSONObj pattern,
                                       mongo_embedded_v1_status& status) {
    if (!library) {
        throw MobileException{MONGO_EMBEDDED_V1_ERROR_LIBRARY_NOT_INITIALIZED,
                              "Cannot create a new database handle when the MongoDB Embedded "
                              "Library is not yet initialized."};
    }

    if (library.get() != lib) {
        throw MobileException{MONGO_EMBEDDED_V1_ERROR_INVALID_LIB_HANDLE,
                              "Cannot create a new database handle when the MongoDB Embedded "
                              "Library is not yet initialized."};
    }

    // BSONObj pattern = BSON("$gt" << 1);
    return new mongo_embedded_v1_matcher(lib->serviceContext->makeClient("stitch_support"),
                                         pattern);
}

int capi_status_get_error(const mongo_embedded_v1_status* const status) noexcept {
    invariant(status);
    return status->error;
}

const char* capi_status_get_what(const mongo_embedded_v1_status* const status) noexcept {
    invariant(status);
    return status->what.c_str();
}

int capi_status_get_code(const mongo_embedded_v1_status* const status) noexcept {
    invariant(status);
    return status->exception_code;
}

template <typename Function,
          typename ReturnType =
              decltype(std::declval<Function>()(*std::declval<mongo_embedded_v1_status*>()))>
struct enterCXXImpl;

template <typename Function>
struct enterCXXImpl<Function, void> {
    template <typename Callable>
    static int call(Callable&& function, mongo_embedded_v1_status& status) noexcept {
        try {
            ReentrancyGuard singleEntrant;
            function(status);
        } catch (...) {
            handleException(status);
        }
        return status.error;
    }
};


template <typename Function, typename Pointer>
struct enterCXXImpl<Function, Pointer*> {
    template <typename Callable>
    static Pointer* call(Callable&& function, mongo_embedded_v1_status& status) noexcept try {
        ReentrancyGuard singleEntrant;
        return function(status);
    } catch (...) {
        return handleException(status);
    }
};
}  // namespace
}  // namespace mongo

namespace {
struct StatusGuard {
private:
    mongo_embedded_v1_status* status;
    mongo_embedded_v1_status fallback;

public:
    explicit StatusGuard(mongo_embedded_v1_status* const statusPtr) noexcept : status(statusPtr) {
        if (status)
            status->clean();
    }

    mongo_embedded_v1_status& get() noexcept {
        return status ? *status : fallback;
    }

    const mongo_embedded_v1_status& get() const noexcept {
        return status ? *status : fallback;
    }

    operator mongo_embedded_v1_status&() & noexcept {
        return this->get();
    }
    operator mongo_embedded_v1_status&() && noexcept {
        return this->get();
    }
};

template <typename Callable>
auto enterCXX(mongo_embedded_v1_status* const statusPtr, Callable&& c) noexcept
    -> decltype(mongo::enterCXXImpl<Callable>::call(std::forward<Callable>(c), *statusPtr)) {
    StatusGuard status(statusPtr);
    return mongo::enterCXXImpl<Callable>::call(std::forward<Callable>(c), status);
}
}  // namespace

extern "C" {
mongo_embedded_v1_lib* MONGO_API_CALL mongo_embedded_v1_lib_init(
    const mongo_embedded_v1_init_params* const params, mongo_embedded_v1_status* const statusPtr) {
    return enterCXX(statusPtr, [&](mongo_embedded_v1_status& status) {
        return mongo::stitch_support_lib_init(params, status);
    });
}

mongo_embedded_v1_matcher* MONGO_API_CALL
mongo_embedded_v1_matcher_create(mongo_embedded_v1_lib* lib,
                                 const char* patternBSON,
                                 mongo_embedded_v1_status* const statusPtr) {
    return enterCXX(statusPtr, [&](mongo_embedded_v1_status& status) {
        mongo::BSONObj pattern(patternBSON);
        return mongo::matcher_new(lib, pattern.getOwned(), status);
    });
}

void MONGO_API_CALL mongo_embedded_v1_matcher_destroy(mongo_embedded_v1_matcher* const matcher) {
    delete matcher;
}


mongo_embedded_v1_error MONGO_API_CALL
mongo_embedded_v1_check_match(mongo_embedded_v1_matcher* matcher,
                              const char* documentBSON,
                              bool* isMatch,
                              mongo_embedded_v1_match_details* matchDetails,
                              mongo_embedded_v1_status* statusPtr) {
    mongo_embedded_v1_status tempStatus;
    if (!statusPtr) {
        statusPtr = &tempStatus;
    }

    enterCXX(statusPtr, [&](mongo_embedded_v1_status& status) {
        if (matchDetails) {
            matchDetails->matchDetails.resetOutput();
        }

        mongo::BSONObj document(documentBSON);
        *isMatch = matcher->matcher.matches(document,
                                            matchDetails ? &matchDetails->matchDetails : nullptr);
    });

    return statusPtr->error;
}

int MONGO_API_CALL
mongo_embedded_v1_status_get_error(const mongo_embedded_v1_status* const status) {
    return mongo::capi_status_get_error(status);
}

const char* MONGO_API_CALL
mongo_embedded_v1_status_get_explanation(const mongo_embedded_v1_status* const status) {
    return mongo::capi_status_get_what(status);
}

int MONGO_API_CALL mongo_embedded_v1_status_get_code(const mongo_embedded_v1_status* const status) {
    return mongo::capi_status_get_code(status);
}

mongo_embedded_v1_status* MONGO_API_CALL mongo_embedded_v1_status_create(void) {
    return new mongo_embedded_v1_status;
}

void MONGO_API_CALL mongo_embedded_v1_status_destroy(mongo_embedded_v1_status* const status) {
    delete status;
}

mongo_embedded_v1_match_details* MONGO_API_CALL mongo_embedded_v1_match_details_create(void) {
    return new mongo_embedded_v1_match_details;
};

void MONGO_API_CALL
mongo_embedded_v1_match_details_destroy(mongo_embedded_v1_match_details* match_details) {
    delete match_details;
};

bool MONGO_API_CALL mongo_embedded_v1_match_details_has_elem_match_path(
    mongo_embedded_v1_match_details* match_details) {
    return match_details->matchDetails.hasElemMatchKey();
}

size_t MONGO_API_CALL mongo_embedded_v1_match_details_elem_match_path_length(
    mongo_embedded_v1_match_details* match_details) {
    invariant(match_details->matchDetails.hasElemMatchKey());
    return match_details->matchDetails.elemMatchPath().size();
}

const char* MONGO_API_CALL mongo_embedded_v1_match_details_elem_match_path_component(
    mongo_embedded_v1_match_details* match_details, size_t index /*,
    bool* out_is_array_index,
    size_t* out_component_as_index*/) {
    invariant(match_details->matchDetails.hasElemMatchKey());
    invariant(index < match_details->matchDetails.elemMatchPath().size());

    auto& component = match_details->matchDetails.elemMatchPath()[index];

#if 0
    if (out_is_array_index) {
        // ...
    }

    if (out_component_as_index) {
        // ...
    }
#endif

    return component.c_str();
}
}  // extern "C"
