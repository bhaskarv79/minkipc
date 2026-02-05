// Copyright (c) 2025, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

      .global    recv_ioctl
      .global    recv_skip
      .global    recv
      .p2align   4

recv_ioctl:
      ldr     r4, [r3]
      cmp     r4, #0
      bne     recv_skip
      mov     r7, #29
recv:
      svc     #0
      bx      lr
recv_skip:
      mov     r0, #-4
      bx      lr

      .end
