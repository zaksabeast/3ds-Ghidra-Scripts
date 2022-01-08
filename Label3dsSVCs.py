# Bookmarks 3ds SVCs and either labels the function or sets a comment
# @category 3ds
#

from ghidra_utils import bytesToByteArr, nameCtrFunc

listing = currentProgram.getListing()
memory = currentProgram.getMemory()

svc_bytes = bytesToByteArr([0x00, 0x00, 0x00, 0xef])
svc_bytes_mask = bytesToByteArr([0x00, 0xff, 0xff, 0xff])

ctr_svcs = {
  0x01: 'svcControlMemory',
  0x02: 'svcQueryMemory',
  0x03: 'svcExitProcess',
  0x04: 'svcGetProcessAffinityMask',
  0x05: 'svcSetProcessAffinityMask',
  0x06: 'svcGetProcessIdealProcessor',
  0x07: 'svcSetProcessIdealProcessor',
  0x08: 'svcCreateThread',
  0x09: 'svcExitThread',
  0x0A: 'svcSleepThread',
  0x0B: 'svcGetThreadPriority',
  0x0C: 'svcSetThreadPriority',
  0x0D: 'svcGetThreadAffinityMask',
  0x0E: 'svcSetThreadAffinityMask',
  0x0F: 'svcGetThreadIdealProcessor',
  0x10: 'svcSetThreadIdealProcessor',
  0x11: 'svcGetCurrentProcessorNumber',
  0x12: 'svcRun',
  0x13: 'svcCreateMutex',
  0x14: 'svcReleaseMutex',
  0x15: 'svcCreateSemaphore',
  0x16: 'svcReleaseSemaphore',
  0x17: 'svcCreateEvent',
  0x18: 'svcSignalEvent',
  0x19: 'svcClearEvent',
  0x1A: 'svcCreateTimer',
  0x1B: 'svcSetTimer',
  0x1C: 'svcCancelTimer',
  0x1D: 'svcClearTimer',
  0x1E: 'svcCreateMemoryBlock',
  0x1F: 'svcMapMemoryBlock',
  0x20: 'svcUnmapMemoryBlock',
  0x21: 'svcCreateAddressArbiter',
  0x22: 'svcArbitrateAddress',
  0x23: 'svcCloseHandle',
  0x24: 'svcWaitSynchronization1',
  0x25: 'svcWaitSynchronizationN',
  0x26: 'svcSignalAndWait',
  0x27: 'svcDuplicateHandle',
  0x28: 'svcGetSystemTick',
  0x29: 'svcGetHandleInfo',
  0x2A: 'svcGetSystemInfo',
  0x2B: 'svcGetProcessInfo',
  0x2C: 'svcGetThreadInfo',
  0x2D: 'svcConnectToPort',
  0x2E: 'svcSendSyncRequest1',
  0x2F: 'svcSendSyncRequest2',
  0x30: 'svcSendSyncRequest3',
  0x31: 'svcSendSyncRequest4',
  0x32: 'svcSendSyncRequest',
  0x33: 'svcOpenProcess',
  0x34: 'svcOpenThread',
  0x35: 'svcGetProcessId',
  0x36: 'svcGetProcessIdOfThread',
  0x37: 'svcGetThreadId',
  0x38: 'svcGetResourceLimit',
  0x39: 'svcGetResourceLimitLimitValues',
  0x3A: 'svcGetResourceLimitCurrentValues',
  0x3B: 'svcGetThreadContext',
  0x3C: 'svcBreak',
  0x3D: 'svcOutputDebugString',
  0x3E: 'svcControlPerformanceCounter',
  0x47: 'svcCreatePort',
  0x48: 'svcCreateSessionToPort',
  0x49: 'svcCreateSession',
  0x4A: 'svcAcceptSession',
  0x4B: 'svcReplyAndReceive1',
  0x4C: 'svcReplyAndReceive2',
  0x4D: 'svcReplyAndReceive3',
  0x4E: 'svcReplyAndReceive4',
  0x4F: 'svcReplyAndReceive',
  0x50: 'svcBindInterrupt',
  0x51: 'svcUnbindInterrupt',
  0x52: 'svcInvalidateProcessDataCache',
  0x53: 'svcStoreProcessDataCache',
  0x54: 'svcFlushProcessDataCache',
  0x55: 'svcStartInterProcessDma',
  0x56: 'svcStopDma',
  0x57: 'svcGetDmaState',
  0x58: 'svcRestartDma',
  0x59: 'svcSetGpuProt',
  0x5A: 'svcSetWifiEnabled',
  0x60: 'svcDebugActiveProcess',
  0x61: 'svcBreakDebugProcess',
  0x62: 'svcTerminateDebugProcess',
  0x63: 'svcGetProcessDebugEvent',
  0x64: 'svcContinueDebugEvent',
  0x65: 'svcGetProcessList',
  0x66: 'svcGetThreadList',
  0x67: 'svcGetDebugThreadContext',
  0x68: 'svcSetDebugThreadContext',
  0x69: 'svcQueryDebugProcessMemory',
  0x6A: 'svcReadProcessMemory',
  0x6B: 'svcWriteProcessMemory',
  0x6C: 'svcSetHardwareBreakPoint',
  0x6D: 'svcGetDebugThreadParam',
  0x70: 'svcControlProcessMemory',
  0x71: 'svcMapProcessMemory',
  0x72: 'svcUnmapProcessMemory',
  0x73: 'svcCreateCodeSet',
  0x74: 'svcRandomStub',
  0x75: 'svcCreateProcess',
  0x76: 'svcTerminateProcess',
  0x77: 'svcSetProcessResourceLimits',
  0x78: 'svcCreateResourceLimit',
  0x79: 'svcSetResourceLimitValues',
  0x7A: 'svcAddCodeSegment',
  0x7B: 'svcBackdoor',
  0x7C: 'svcKernelSetState',
  0x7D: 'svcQueryProcessMemory',
  0xFF: 'svcStopPoint',
}

start_address = memory.getExecuteSet().getMaxAddress()

while True:
  svc_instruction_addr = memory.findBytes(start_address, svc_bytes, svc_bytes_mask, False, monitor)

  if svc_instruction_addr is None:
    break

  svc_instruction_code = listing.getCodeUnitAt(svc_instruction_addr)

  if svc_instruction_code is not None:
    svc_id = svc_instruction_code.getBytes()[0]
    svc_name = ctr_svcs.get(svc_id)

    if svc_name is None:
      # Could be data that was misinterpretted
      start_address = svc_instruction_addr.subtract(4)
      continue

    # Show user current location in case we need to about inlining
    setCurrentLocation(svc_instruction_addr)

    if (
      svc_name == 'svcGetSystemTick' or
      svc_name == 'svcClearEvent' or
      svc_name == 'svcCloseHandle' or
      svc_name == 'svcSignalEvent' or
      svc_name == 'svcExitProcess' or
      'svcSendSyncRequest' in svc_name or
      'svcWaitSynchronization' in svc_name
    ):
      rename_to_svc = False
    else:
      # TODO: Be smarter about finding inlinved svcs.  That shouldn't be too hard to do.
      rename_to_svc = askYesNo('SVC Function Namer', 'Rename the current function to be the SVC?\nClicking no will create a comment instead.')

    if rename_to_svc:
      func = getFunctionAt(svc_instruction_addr)
      func = func if func is not None else getFunctionBefore(svc_instruction_addr)
      nameCtrFunc(func, svc_name)
    else:
      svc_instruction_code.setComment(svc_instruction_code.PRE_COMMENT, svc_name)
      print('Bookmarked {} at {}'.format(svc_name, svc_instruction_addr.toString()))

    createBookmark(svc_instruction_addr, 'SVC', svc_name)

  start_address = svc_instruction_addr.subtract(4)
