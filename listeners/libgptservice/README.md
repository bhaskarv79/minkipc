# GPT Service for MINK IPC Framework

## Overview

The GPT (GUID Partition Table) service is a secure listener service for the MINK IPC framework that provides GPT partition management capabilities to QTEE (Qualcomm Trusted Execution Environment) applications. This service allows trusted applications to securely read, verify, and manage GPT partition tables on storage devices.

## Features

The GPT service provides the following capabilities:

### Core GPT Operations
- **Read GPT Header**: Read and parse GPT header information from storage devices
- **Write GPT Header**: Write updated GPT header information (with proper validation)
- **Read Partition Table**: Read the complete partition table entries
- **Get Partition Info**: Retrieve detailed information about specific partitions
- **Verify Integrity**: Validate GPT header and partition table integrity using CRC32 checksums
- **Get Disk Info**: Retrieve disk geometry and basic information

### Security Features
- Runs in the secure QTEE environment through MINK IPC
- Validates GPT signatures and checksums
- Provides secure access to partition information
- Supports both primary and backup GPT verification

## Architecture

```
┌─────────────────┐    MINK IPC    ┌─────────────────┐
│   QTEE App      │◄──────────────►│  GPT Service    │
│                 │                │  (REE Listener) │
└─────────────────┘                └─────────────────┘
                                            │
                                            ▼
                                   ┌─────────────────┐
                                   │  Block Device   │
                                   │  (/dev/sdX)     │
                                   └─────────────────┘
```

## Message Protocol

The service uses a command-response protocol with the following message types:

### Commands
- `TZ_GPT_MSG_CMD_GPT_READ_HEADER` - Read GPT header
- `TZ_GPT_MSG_CMD_GPT_WRITE_HEADER` - Write GPT header
- `TZ_GPT_MSG_CMD_GPT_READ_PARTITION_TABLE` - Read partition table
- `TZ_GPT_MSG_CMD_GPT_GET_PARTITION_INFO` - Get partition information
- `TZ_GPT_MSG_CMD_GPT_VERIFY_INTEGRITY` - Verify GPT integrity
- `TZ_GPT_MSG_CMD_GPT_GET_DISK_INFO` - Get disk information
- `TZ_GPT_MSG_CMD_GPT_END` - End service session

### Data Structures

#### GPT Header (`tz_gpt_header_t`)
Contains standard GPT header fields including:
- GPT signature ("EFI PART")
- Revision and header size
- Current and backup LBA locations
- Usable LBA range
- Disk GUID
- Partition table location and size

#### Partition Entry (`tz_gpt_partition_entry_t`)
Standard GPT partition entry with:
- Partition type GUID
- Unique partition GUID
- Starting and ending LBA
- Partition attributes
- Partition name (UTF-16)

#### Partition Info (`tz_gpt_partition_info_t`)
Simplified partition information for userspace:
- Partition name (UTF-8)
- Type and unique GUIDs
- LBA range and size in bytes
- Attributes and index

## Building

The GPT service is built as part of the MINK IPC framework:

```bash
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=CMakeToolchain.txt -DBUILD_GPT_LISTENER=ON
cmake --build . --target install --config Release
```

### Dependencies

#### zlib (for CRC32 calculations)
- **Ubuntu/Debian**: `sudo apt-get install zlib1g-dev`
- **Fedora/RHEL**: `sudo yum install zlib-devel`
- **Source**: https://github.com/madler/zlib
- **Cross-compile**: Available in most cross-compilation toolchains (e.g., Yocto SDK)

#### uuid (for GUID operations)
- **Ubuntu/Debian**: `sudo apt-get install uuid-dev`
- **Fedora/RHEL**: `sudo yum install libuuid-devel`
- **Source**: Part of util-linux: https://github.com/util-linux/util-linux
- **Cross-compile**: Available in most cross-compilation toolchains (e.g., Yocto SDK)

#### For Yocto/OpenEmbedded builds:
Add to your recipe's `DEPENDS`:
```
DEPENDS += "zlib util-linux"
```

### Block Device Requirements

The GPT service operates on standard Linux block devices that contain GPT partition tables:

#### Supported Block Devices:
- **eMMC devices**: `/dev/mmcblk0`, `/dev/mmcblk1`, etc.
- **UFS devices**: `/dev/sda`, `/dev/sdb`, etc. (via SCSI/UFS subsystem)
- **NVMe devices**: `/dev/nvme0n1`, etc.

#### Device Access:
- The service requires read access to the block device
- Write operations (if enabled) require write permissions
- Typically requires root or appropriate udev rules for access

#### Kernel Requirements:
- Block device support must be enabled in the kernel
- For eMMC: `CONFIG_MMC_BLOCK`
- For UFS: `CONFIG_SCSI_UFSHCD`
- GPT partition support: `CONFIG_PARTITION_ADVANCED` and `CONFIG_EFI_PARTITION`

#### Example Device Paths:
- **Qualcomm platforms with eMMC**: `/dev/mmcblk0` (main storage)
- **Qualcomm platforms with UFS**: `/dev/sda` or `/dev/disk/by-partlabel/...`

The service validates device paths and checks for GPT signatures before performing operations.

## Usage

### Service Registration
The GPT service is automatically registered with the QTEE supplicant when `BUILD_GPT_LISTENER` is enabled. The service listens on service ID `0xc` with a 20KB buffer.

### Integration with QTEE Applications
QTEE applications can use the GPT service through the MINK IPC framework:

```c
// Example: Get partition information
tz_gpt_get_partition_info_req_t req;
tz_gpt_get_partition_info_rsp_t rsp;

req.cmd_id = TZ_GPT_MSG_CMD_GPT_GET_PARTITION_INFO;
strncpy(req.device_path, "/dev/mmcblk0", sizeof(req.device_path) - 1);
strncpy(req.partition_name, "system", sizeof(req.partition_name) - 1);

// Send request through MINK IPC
// ... (MINK IPC call)

if (rsp.ret == 0) {
    printf("Partition %s: %lu bytes\n", 
           rsp.partition_info.name, 
           rsp.partition_info.size_bytes);
}
```

## Security Considerations

### Access Control
- The service runs in the REE (Rich Execution Environment) but is accessed only through the secure QTEE
- QTEE applications must have appropriate permissions to access the GPT service
- Device paths are validated to prevent unauthorized access

### Data Integrity
- All GPT operations include CRC32 validation
- Both primary and backup GPT structures are verified
- Invalid or corrupted GPT data is rejected

### Error Handling
- Comprehensive error checking for all disk operations
- Proper cleanup of file descriptors and memory
- Detailed error reporting through return codes

## Limitations

- Read-only operations are prioritized for security
- Write operations require additional validation
- Limited to GPT-formatted disks (no MBR support)
- Requires appropriate permissions for block device access

## Testing

Testing of the GPT listener service should be performed using a Trusted Application (TA) that invokes the service through QTEE. This ensures proper end-to-end validation of the MINK IPC communication path and service functionality.

## Files

- `gpt_msg.h` - Message protocol definitions
- `gpt_service.c` - Main service implementation
- `gpt_logging.c/h` - Logging utilities
- `CMakeLists.txt` - Build configuration
- `README.md` - This documentation

## Future Enhancements

Potential future improvements include:
- Partition creation and deletion support
- Partition resizing capabilities
- Advanced backup and restore operations
- Support for encrypted partition metadata
- Integration with secure boot verification

## License

Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
SPDX-License-Identifier: BSD-3-Clause-Clear
