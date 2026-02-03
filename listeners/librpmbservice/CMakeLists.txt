project(librpmbservice
	VERSION 1.0.0
	LANGUAGES C
)

add_compile_options(
	-Wstrict-prototypes -Wmissing-prototypes -Wbad-function-cast
)

# Enable this line for debug purpose, it will enable console prints and disable syslog
# add_definitions(-DRPMB_DEBUG_CONSOLE_OUTPUT)

# Source files - Legacy RPMB architecture (working)
set(SRC
	../listenercbo/src/CListenerCBO.c
	../listenercbo/src/memscpy.h
	rpmb_service.c
	rpmb_msg.h
	rpmb.c
	rpmb_core.c
	rpmb_ufs.c
	rpmb_emmc.c
	rpmb_logging.c
	rpmb_detect.c
)

add_library(rpmbservice SHARED ${SRC})

# Library version
set_target_properties(rpmbservice PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Add dependency on listenercbo for MINK IPC headers
add_dependencies(rpmbservice listenercbo_MINKHEADERS)

target_include_directories(rpmbservice
	PRIVATE ../listenercbo/include
	PRIVATE ../listenercbo/idl
	PRIVATE ${CMAKE_SOURCE_DIR}/libminkadaptor/include
)

target_link_libraries(rpmbservice
	PRIVATE minkadaptor
)


# Install targets
install(TARGETS rpmbservice
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
