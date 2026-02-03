# RPMB Service for MINK IPC Framework

## Overview

The RPMB (Replay Protected Memory Block) service provides secure storage capabilities through the MINK IPC framework. RPMB is a hardware-based secure storage feature available in eMMC and UFS storage devices that provides authenticated and replay-protected data storage.

## Features

### Core RPMB Operations
- **Key Programming**: One-time programming of authentication key
- **Write Counter**: Monotonic counter to prevent replay attacks
- **Authenticated Data Write**: Secure data storage with HMAC authentication
- **Authenticated Data Read**: Secure data retrieval with integrity verification
- **Device Information**: Query RPMB device capabilities
- **Key Verification**: Verify programmed authentication key

### Security Features
- **HMAC-SHA256 Authentication**: All operations use HMAC-SHA256 for authentication
- **Replay Protection**: Monotonic write counter prevents replay attacks
- **Hardware Security**: Leverages eMMC/UFS RPMB hardware security features
- **One-time Key Programming**: Authentication key can only be programmed once
- **Secure Communication**: All operations go through QTEE trusted execution environment

## Architecture

The RPMB service follows the standard MINK IPC listener pattern:

```
QTEE Application
       ↓
   MINK IPC
       ↓
QTEE Supplicant
       ↓
RPMB Listener (librpmbservice.so.1)
       ↓
MMC/UFS RPMB Hardware
```

### Service Registration
- **Service ID**: 0xd
- **Buffer Size**: 20KB
- **Library**: librpmbservice.so.1
- **Dispatch Function**: smci_dispatch

## Message Protocol

### Command Types
```c
typedef enum {
    TZ_RPMB_MSG_CMD_RPMB_PROGRAM_KEY,      // Program authentication key
    TZ_RPMB_MSG_CMD_RPMB_GET_WRITE_COUNTER, // Get write counter
    TZ_RPMB_MSG_CMD_RPMB_WRITE_DATA,       // Write authenticated data
    TZ_RPMB_MSG_CMD_RPMB_READ_DATA,        // Read authenticated data
    TZ_RPMB_MSG_CMD_RPMB_GET_DEVICE_INFO,  // Get device information
    TZ_RPMB_MSG_CMD_RPMB_VERIFY_KEY,       // Verify authentication key
    TZ_RPMB_MSG_CMD_RPMB_END,              // End service
} tz_rpmb_msg_cmd_type;
```

### Data Structures
- **RPMB Frame**: Standard 512-byte RPMB frame structure
- **Device Info**: RPMB device capabilities and configuration
- **Request/Response**: Command-specific request and response structures

## Usage Example

### QTEE Application Usage
```c
// Program RPMB key (one-time operation)
tz_rpmb_program_key_req_t key_req;
key_req.cmd_id = TZ_RPMB_MSG_CMD_RPMB_PROGRAM_KEY;
strncpy(key_req.device_path, "/dev/mmcblk0rpmb", sizeof(key_req.device_path)-1);
memcpy(key_req.key, authentication_key, RPMB_KEY_SIZE);
// Send via MINK IPC to RPMB service

// Write secure data
tz_rpmb_write_data_req_t write_req;
write_req.cmd_id = TZ_RPMB_MSG_CMD_RPMB_WRITE_DATA;
strncpy(write_req.device_path, "/dev/mmcblk0rpmb", sizeof(write_req.device_path)-1);
write_req.address = 0;
write_req.block_count = 1;
memcpy(write_req.data, secure_data, RPMB_DATA_SIZE);
memcpy(write_req.key, authentication_key, RPMB_KEY_SIZE);
// Send via MINK IPC to RPMB service

// Read secure data
tz_rpmb_read_data_req_t read_req;
read_req.cmd_id = TZ_RPMB_MSG_CMD_RPMB_READ_DATA;
strncpy(read_req.device_path, "/dev/mmcblk0rpmb", sizeof(read_req.device_path)-1);
read_req.address = 0;
read_req.block_count = 1;
generate_nonce(read_req.nonce);
// Send via MINK IPC to RPMB service
```

## Build Instructions

### Prerequisites
- OpenSSL development libraries
- CMake 3.10 or higher
- Linux kernel headers (for MMC IOCTL definitions)

### Building
```bash
# Configure with RPMB listener enabled
cmake .. -DBUILD_RPMB_LISTENER=ON

# Build the service
make rpmbservice

```

### Installation
```bash
# Install service library
make install

# The service will be installed as:
# - /usr/local/lib/librpmbservice.so.1
# - /usr/local/include/rpmb_msg.h
```

## Security Considerations

### Key Management
- **One-time Programming**: RPMB key can only be programmed once
- **Secure Key Storage**: Keys should be stored securely in QTEE
- **Key Derivation**: Consider using key derivation functions for application-specific keys

### Replay Protection
- **Monotonic Counter**: Write counter prevents replay attacks
- **Nonce Usage**: Use random nonces for read operations
- **MAC Verification**: Always verify HMAC for data integrity

### Access Control
- **Device Permissions**: Ensure proper permissions on RPMB device nodes
- **QTEE Integration**: All operations should go through QTEE for security
- **Application Isolation**: Different applications should use different key derivations

## Hardware Requirements

### Supported Devices
- **eMMC**: eMMC devices with RPMB support
- **UFS**: UFS devices with RPMB support
- **Device Nodes**: Typically `/dev/mmcblk0rpmb` or `/dev/block/mmcblk0rpmb`

### RPMB Specifications
- **Data Size**: 256 bytes per block
- **Authentication**: HMAC-SHA256
- **Counter**: 32-bit monotonic write counter
- **Address Space**: Device-dependent (typically 128KB - 16MB)

## Integration with QTEE

### Service Registration
The RPMB service automatically registers with the QTEE supplicant when enabled:
- Compile with `-DBUILD_RPMB_LISTENER=ON`
- Service starts automatically with qtee_supplicant
- Available to QTEE applications via MINK IPC

### Error Handling
- **RPMB Result Codes**: Standard RPMB result codes for operation status
- **Return Values**: Service-level return codes for IPC status
- **Error Logging**: Comprehensive error logging for debugging

## Future Enhancements

### Planned Features
- **Multi-block Operations**: Support for reading/writing multiple blocks
- **Secure Write/Read**: Enhanced secure operations with additional validation
- **Key Derivation**: Built-in key derivation functions
- **Access Control**: Fine-grained access control for different applications

### Performance Optimizations
- **Batch Operations**: Support for batching multiple RPMB operations
- **Caching**: Intelligent caching of device information
- **Async Operations**: Asynchronous operation support

## Troubleshooting

### Common Issues
1. **Device Access**: Ensure RPMB device node has proper permissions
2. **Key Programming**: Remember that key programming is one-time only
3. **Authentication Failures**: Verify key consistency across operations
4. **Counter Mismatches**: Ensure write counter synchronization

### Debug Information
- Enable debug logging with `MSGD` macros
- Check RPMB result codes in responses
- Verify device capabilities with device info command
- Monitor MMC/UFS driver logs for hardware issues

## References

- [JEDEC eMMC Specification](https://www.jedec.org/standards-documents/docs/jesd84-b51)
- [JEDEC UFS Specification](https://www.jedec.org/standards-documents/docs/jesd220)
- [Linux MMC Subsystem Documentation](https://www.kernel.org/doc/html/latest/driver-api/mmc/index.html)
- [MINK IPC Framework Documentation](../../../docs/)
