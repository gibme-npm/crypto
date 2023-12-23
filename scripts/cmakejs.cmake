# Authored by Graham Dianaty for Bitlogix Technologies. Based on code from Rene Hollander. ==========//
function(setup_cmakejs)
    find_program(NODE "node")
    find_program(CMAKEJS "cmake-js")
    find_program(NPM "npm")
    # first, check if we have Node
    if(NODE)
        message(STATUS "Node.js found")
    else()
        message(FATAL_ERROR "Node.js not found. This project requires Node.js")
    endif()

    if(NPM)
        message(STATUS "NPM found.")
    else()
        message(FATAL_ERROR "NPM not found. This project requires Node.js")
    endif()

    if(CMAKEJS)
        message(STATUS "CMake.js found.")
    else()
        message(ERROR "CMake.js not found, installing globally...")
        exec_program(${NPM_COMMAND} ${CMAKE_CURRENT_SOURCE_DIR} ARGS install -g cmake-js OUTPUT_VARIABLE NPM_OUTPUT)
        message(STATUS "CMake.js should now be installed.")
        message(VERBOSE ${NPM_OUTPUT})
    endif()

    if(WIN32)
        set(NPM_COMMAND ${NPM}.cmd)
        set(CMAKEJS_CMD ${CMAKEJS}.cmd)
    else()
        set(NPM_COMMAND ${NPM})
        set(CMAKEJS_CMD ${CMAKEJS})
    endif()

    string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)
    if (CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
        execute_process(
                COMMAND "${NODE}" "${PROJECT_SOURCE_DIR}/scripts/cmakejs.js" "${CMAKEJS_CMD}" "debug"
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                OUTPUT_VARIABLE CMAKE_JS_OUTPUT
                ERROR_QUIET
                #"${CMAKEJS_CMD}" ${CMAKE_CURRENT_SOURCE_DIR}
                #ARGS print-configure --debug
                #OUTPUT_VARIABLE CMAKE_JS_OUTPUT
        )
    else()
        execute_process(
                COMMAND "${NODE}" "${PROJECT_SOURCE_DIR}/scripts/cmakejs.js" "${CMAKEJS_CMD}"
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                OUTPUT_VARIABLE CMAKE_JS_OUTPUT
                ERROR_QUIET
                #"${CMAKEJS_CMD}" ${CMAKE_CURRENT_SOURCE_DIR}
                #ARGS print-configure
                #OUTPUT_VARIABLE CMAKE_JS_OUTPUT
        )
    endif ()

    message(VERBOSE ${CMAKE_JS_OUTPUT})

    set(CMAKE_JS_DEFINITIONS "")

    foreach(VAR IN LISTS CMAKE_JS_OUTPUT)
        string(REPLACE "=" ";" VAR_LIST "${VAR}")
        list(GET VAR_LIST 0 VAR_LEFT)
        list(GET VAR_LIST 1 VAR_RIGHT)
        set("${VAR_LEFT}" "${${VAR_LEFT}};${VAR_RIGHT}")
        list(APPEND CMAKE_JS_DEFINITIONS "${VAR_LEFT}")
    endforeach()

    foreach(CMAKE_JS_DEFINITION IN LISTS CMAKE_JS_DEFINITIONS)
        set(${CMAKE_JS_DEFINITION} ${${CMAKE_JS_DEFINITION}} PARENT_SCOPE)
    endforeach()

    #get_variable("${CMAKE_JS_OUTPUT}" "CMAKE_JS_INC" CMAKE_JS_INC)
    #set(CMAKE_JS_INC "${CMAKE_JS_INC}" PARENT_SCOPE)

    #get_variable("${CMAKE_JS_OUTPUT}" "CMAKE_JS_LIB" CMAKE_JS_LIB)
    #set(CMAKE_JS_LIB "${CMAKE_JS_LIB}" PARENT_SCOPE)

    #get_variable("${CMAKE_JS_OUTPUT}" "CMAKE_LIBRARY_OUTPUT_DIRECTORY" CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    #set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}" PARENT_SCOPE)

    #get_variable("${CMAKE_JS_OUTPUT}" "CMAKE_JS_VERSION" CMAKE_JS_VERSION)
    #set(CMAKE_JS_VERSION "${CMAKE_JS_VERSION}" PARENT_SCOPE)

    message(STATUS "[CMakeJS] Set up variables.")
endfunction(setup_cmakejs)
