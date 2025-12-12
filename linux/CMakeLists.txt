find_package(PkgConfig REQUIRED)
pkg_check_modules(DBUS REQUIRED dbus-1)
pkg_check_modules(BLUEZ REQUIRED bluez)
pkg_check_modules(PIPEWIRE REQUIRED libpipewire-0.3)

add_executable(airpods
    main.cpp
    bluez.cpp
    l2cap.cpp
    pipewire.cpp
    dbus.cpp
)

target_link_libraries(airpods
    PRIVATE
        airpods_common
        ${DBUS_LIBRARIES}
        ${BLUEZ_LIBRARIES}
        ${PIPEWIRE_LIBRARIES}
)

target_include_directories(airpods
    PRIVATE
        ${DBUS_INCLUDE_DIRS}
        ${BLUEZ_INCLUDE_DIRS}
        ${PIPEWIRE_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(airpods PRIVATE ${DBUS_CFLAGS_OTHER} ${BLUEZ_CFLAGS_OTHER} ${PIPEWIRE_CFLAGS_OTHER})

install(TARGETS airpods RUNTIME DESTINATION bin)

# Systemd user service
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/airpods.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/airpods.service
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/airpods.service
    DESTINATION lib/systemd/user)
