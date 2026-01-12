project(gp_test_client C)

# ''Packages''.

find_package(Threads REQUIRED)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "Threads not found")
endif()

# ''Build IDL Headers''.

set (IDLS
	idl/CAppLoader
	idl/IAppController
	idl/IAppLoader
	idl/IClientEnv
	idl/ICredentials
	idl/IIO
)

foreach(IDL ${IDLS})
	foreach(VARIANT "" "--skel" )
		if (VARIANT)
			set(INVOKE _invoke)
		else()
			set(INVOKE "")
		endif()

		set(IDL_OUT ${CMAKE_CURRENT_SOURCE_DIR}/${IDL}${INVOKE}.h)
		set(INPUT ${CMAKE_CURRENT_SOURCE_DIR}/${IDL}.idl)

		add_custom_command(
			OUTPUT  ${IDL_OUT}
			DEPENDS ${INPUT}
			COMMAND ${MINKIDLC_BIN_DIR}/idlc ${INPUT} -o ${IDL_OUT} ${VARIANT}
		)

		list(APPEND IDL_OUT_LIST ${IDL_OUT})
	endforeach()
endforeach()

# A custom target to build the MINK-HEADERS which is always out of date.
add_custom_target(
        ${PROJECT_NAME}_MINKHEADERS ALL
        DEPENDS ${IDL_OUT_LIST}
)

# ''Source files''.

set(SRC
	src/gp_test_client.c
	src/gp_load_ta.c
)

# ''Built binary''.

add_executable(${PROJECT_NAME} ${SRC})

# The binary depends on the MINK-IDLs
add_dependencies(${PROJECT_NAME} ${PROJECT_NAME}_MINKHEADERS)

# ''Headers and dependencies''.

target_include_directories(${PROJECT_NAME}
	PRIVATE src
	PRIVATE idl
)

target_link_libraries(${PROJECT_NAME}
	PRIVATE minkteec
	PRIVATE minkadaptor
	PRIVATE ${CMAKE_THREAD_LIBS_INIT}
)

install(TARGETS ${PROJECT_NAME} DESTINATION "${CMAKE_INSTALL_BINDIR}")
