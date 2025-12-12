find_package(OpenSSL REQUIRED)

add_library(airpods_common STATIC
    protocol/crypto.cpp
    protocol/parse.cpp
)

target_include_directories(airpods_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(airpods_common
    PUBLIC OpenSSL::Crypto
)

target_compile_features(airpods_common PUBLIC cxx_std_23)
