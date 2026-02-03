cmake_minimum_required(VERSION 3.10)
project(minkipc)

# Build Mink TEEC library
option(BUILD_MINKTEEC "Build MinkTEEC" TRUE)

option(BUILD_UNITTEST "Build unittest" FALSE)

# Build Time listener
option(BUILD_TIME_LISTENER "Build Time Listener" TRUE)
# Build TA Autoload listener
option(BUILD_TA_AUTOLOAD_LISTENER "Build TA autoload Listener" TRUE)
# Build File system listener
option(BUILD_FS_LISTENER "Build File system Listener" TRUE)
# Build Secure File system listener
option(BUILD_GPFS_LISTENER "Build GP File system Listener" TRUE)
# Use GLib for strlcat/strlcpy fallback
option(USE_GLIB "Use GLIB functions" FALSE)
# Use pkg-config for discovering install target directory
option(CFG_USE_PKGCONFIG "Use pkg-config for discovering install target directory for systemd and udev files." OFF)
# Build RPMB listener
option(BUILD_RPMB_LISTENER "Build RPMB Listener" TRUE)

include(GNUInstallDirs)

set(MINKIDLC_BIN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/idlc" CACHE PATH "Directory containing the idlc executable")
set(SYSTEMD_UNIT_DIR "" CACHE PATH "Directory containing the systemd unit path")
set(UDEV_DIR "" CACHE PATH "Directory containing the UDEV path")

if ("${MINKIDLC_BIN_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}/idlc")
	file(DOWNLOAD
	https://github.com/quic/mink-idl-compiler/releases/download/v0.2.0/idlc
	${MINKIDLC_BIN_DIR}/idlc
	)
endif()

file(CHMOD ${MINKIDLC_BIN_DIR}/idlc PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)

add_compile_options(
	-Wall -Wextra -Werror -Wshadow -Wcast-align
	-Wmissing-declarations -Wformat-security -Wmissing-noreturn
	-Wdeprecated -fPIC
)

add_subdirectory(libminkadaptor)

if (BUILD_MINKTEEC)
	add_subdirectory(libminkteec)
endif()

add_subdirectory(qtee_supplicant)
add_subdirectory(listeners/listenercbo)

if(BUILD_TIME_LISTENER)
	add_subdirectory(listeners/libtimeservice)
endif()

if(BUILD_TA_AUTOLOAD_LISTENER)
	add_subdirectory(listeners/libtaautoload)
endif()

if(BUILD_FS_LISTENER OR BUILD_GPFS_LISTENER)
	add_subdirectory(listeners/libfsservice)
endif()

if(BUILD_RPMB_LISTENER)
	add_subdirectory(listeners/librpmbservice)
endif()
