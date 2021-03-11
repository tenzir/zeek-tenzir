cmake_minimum_required(VERSION 3.14...3.19 FATAL_ERROR)

project(zeek-to-vast
  DESCRIPTION "zeek-to-vast relay utility"
  LANGUAGES CXX)

find_package(vast REQUIRED)

# TODO: Remove option to use bundled Broker and the Broker submodule. Requires
# using a different start value for type IDs than Broker, i.e., not
# caf::first_custom_type_id.

option(VAST_ENABLE_BUNDLED_BROKER "Always use the Broker submodule" OFF)
add_feature_info("VAST_ENABLE_BUNDLED_BROKER" VAST_ENABLE_BUNDLED_BROKER
                 "always use the Broker submodule.")

if (NOT VAST_ENABLE_BUNDLED_BROKER)
  find_package(BROKER 1.3.1 EXACT)
  if (NOT BROKER_FOUND)
    message(WARNING "Broker not found; falling back to bundled version")
  endif ()
endif ()

if (NOT BROKER_FOUND)
  if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/aux/broker/broker/CMakeLists.txt")
    add_subdirectory(aux/broker)
    set(broker_dir "${CMAKE_CURRENT_SOURCE_DIR}/aux/broker")
  else ()
    message(
      FATAL_ERROR
        "Broker not found, either use -DBROKER_ROOT_DIR=... or initialize the aux/broker/broker submodule"
    )
  endif ()
endif ()

add_executable(zeek-to-vast zeek-to-vast.cpp)
target_link_libraries(zeek-to-vast PRIVATE vast::libvast vast::internal
                                           zeek::broker CAF::core)
if (NOT broker_dir)
  get_target_property(broker_dir zeek::broker IMPORTED_LOCATION)
endif ()
dependency_summary("Broker" "${broker_dir}")

install(TARGETS zeek-to-vast DESTINATION "${CMAKE_INSTALL_BINDIR}")
