project(libgptservice
	VERSION 1.0.0
	LANGUAGES C
)

add_compile_options(
	-Wstrict-prototypes -Wmissing-prototypes -Wbad-function-cast
)

# Source files
set(SRC
	../listenercbo/src/CListenerCBO.c
	../listenercbo/src/memscpy.h
	gpt_service.c
	gpt_msg.h
	gpt_logging.c
)

add_library(gptservice SHARED ${SRC})

# Library version
set_target_properties(gptservice PROPERTIES
	VERSION ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Add dependency on listenercbo for MINK IPC headers
add_dependencies(gptservice listenercbo_MINKHEADERS)

target_include_directories(gptservice
	PRIVATE ../listenercbo/include
	PRIVATE ../listenercbo/idl
	PRIVATE ${CMAKE_SOURCE_DIR}/libminkadaptor/include
)

target_link_libraries(gptservice
	PRIVATE minkadaptor
)

# Install the shared library
install(TARGETS gptservice
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
