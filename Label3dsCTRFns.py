# Labels 3ds CTR lib functions
# @category 3ds
#

from collections import Counter
from ghidra_utils import bytesToByteArr, nameCtrFunc, findFirstByteArray, readBytes, getCallArgs, getValueFromConstantVarnode, getOrCreateNamespace
from ctr_services import getCommandName, service_handle_names

listing = currentProgram.getListing()
memory = currentProgram.getMemory()

def makeIpcHeader(command_id, normal_params, translate_params):
  return command_id << 16 | (normal_params & 0x3f) << 6 | translate_params & 0x3f

def parseIpcVarNode(varnode):
  addr = varnode.getAddress()
  if addr.isRegisterAddress():
    return None
  if addr.isConstantAddress():
    return addr.getOffset()
  return memory.getInt(addr)

def nameIpcFunc(ipc_func, ipc_header, handle):
    func_name = getCommandName(ipc_header, handle)
    nameCtrFunc(ipc_func, func_name)

def nameIpcWrapperFunc(ipc_func, ipc_header, handle):
    func_name = getCommandName(ipc_header, handle)
    nameCtrFunc(ipc_func, func_name + '_wrapper')

def getConstantFromMov(mov_addr):
  inst = listing.getInstructionContaining(mov_addr)
  if inst is not None:
    pcode_ops = inst.getPcode()
    for pcode_op in pcode_ops:
      if pcode_op.getMnemonic() == 'COPY':
        varnode = pcode_op.getInputs()[0]
        return getValueFromConstantVarnode(varnode)
  return None

def getIpcHeaderFromAddr(addr):
  ipc_header = getConstantFromMov(addr)
  if ipc_header is None:
    ipc_store_refs = getReferencesFrom(addr)
    if len(ipc_store_refs) > 0:
      ipc_header_addr = ipc_store_refs[0].getToAddress()
      ipc_header = memory.getInt(ipc_header_addr)
  return ipc_header

ctr_namespace = getOrCreateNamespace('ctr')

handles_by_caller_funcs = {}
for handle_name in service_handle_names:
  handles = getSymbols(handle_name, ctr_namespace)
  for handle in handles:
    refs = getReferencesTo(handle.getAddress())
    for ref in refs:
      handle_name = handle.getName()
      from_addr = ref.getFromAddress()
      func_ref = getFunctionContaining(from_addr)
      if func_ref is not None:
        func_addr = func_ref.getEntryPoint()
        handles_by_caller_funcs[func_addr] = handle_name

def getHandleOfIpcCommand(ipc_func):
  return handles_by_caller_funcs.get(ipc_func.getEntryPoint())

# ---------------------------------------------------------------------------
# IPC functions using ipc_set_header
ipc_set_header_bytes = [0x10, 0xb5, 0x04, 0x46, 0x08, 0x46, 0x11, 0x46, 0x1a, 0x46, 0x02, 0x9b, 0xff, 0xff, 0xff, 0xff, 0x21, 0x68, 0x08, 0x60, 0x10, 0xbd]
ipc_set_header_mask = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
ipc_set_header_addr = findFirstByteArray(ipc_set_header_bytes, ipc_set_header_mask)

if ipc_set_header_addr is None:
  ipc_make_header_refs = []
else:
  ipc_make_header_refs = getReferencesTo(ipc_set_header_addr)

if ipc_make_header_refs is None:
  ipc_make_header_refs = []

result = []
for ref in ipc_make_header_refs:
  func = getFunctionContaining(ref.getFromAddress())
  if func is not None:
    result.append(func)
  else:
    print('Cannot find function for {}.  Could this be part of a service command handler jump table?'.format(ref.getFromAddress()))

ipc_make_header_refs = result

dupliate_ipc_make_header_refs = []
unique_ipc_make_header_refs = []

for ref, count in Counter(ipc_make_header_refs).items():
  if count > 1:
    dupliate_ipc_make_header_refs.append(ref)
  else:
    unique_ipc_make_header_refs.append(ref)

# If a function sets a header multiple times, it's likely a command handler
for ipc_func in dupliate_ipc_make_header_refs:
  nameCtrFunc(ipc_func, 'handleServiceCommand')

for ipc_func in unique_ipc_make_header_refs:
  args = getCallArgs(ipc_func, ipc_set_header_addr)
  if len(args) < 4:
    print('Bad number of args at {}'.format(ipc_set_header_addr))
  else:
    command_id = parseIpcVarNode(args[1])
    normal_params = parseIpcVarNode(args[2])
    translate_params = parseIpcVarNode(args[3])
    if command_id is not None and normal_params is not None and translate_params is not None:
      ipc_header = makeIpcHeader(command_id, normal_params, translate_params)
      handle = getHandleOfIpcCommand(ipc_func)
      nameIpcFunc(ipc_func, ipc_header, handle)

# ---------------------------------------------------------------------------
# IPC functions using inlined svc_sync_sync_request
svc_send_sync_request = bytesToByteArr([0x32, 0x00, 0x00, 0xef])
svc_send_sync_request_mask = bytesToByteArr([0xff, 0xff, 0xff, 0xff])

func_start_bytes = bytesToByteArr([0x00, 0x00, 0x0d, 0xe9])
func_start_mask = bytesToByteArr([0x00, 0x00, 0x0f, 0xff])

get_thread_local_storage_bytes = bytesToByteArr([0x70, 0x4f, 0x1d, 0xee])
get_thread_local_storage_mask = bytesToByteArr([0xff, 0x0f, 0xff, 0xff])

start_address = memory.getExecuteSet().getMaxAddress()
while start_address is not None:
  svc_send_sync_request_addr = memory.findBytes(start_address, svc_send_sync_request, svc_send_sync_request_mask, False, monitor)

  if svc_send_sync_request_addr is None:
    # No more functions
    break

  if readBytes(svc_send_sync_request_addr.add(4), 4) == bytesToByteArr([0x1e, 0xff, 0x2f, 0xe1]):
    # Non-inlined svcSendSyncRequest
    start_address = None
    continue

  ipc_func_addr = memory.findBytes(svc_send_sync_request_addr, func_start_bytes, func_start_mask, False, monitor)

  if ipc_func_addr is None:
    # No more functions
    break

  wrapper_func = None
  ipc_func = getFunctionContaining(ipc_func_addr)

  if ipc_func is None:
    # Bad data
    # We should probably check the section before assuming this
    break

  if not ipc_func.getEntryPoint().equals(ipc_func_addr):
    wrapper_func = ipc_func
    ipc_func = createFunction(ipc_func_addr, 'UNKNOWN_CTR_IPC_FN')

  ipc_func_body = ipc_func.getBody()
  ipc_func_start = ipc_func_body.getMinAddress()
  ipc_func_end = ipc_func_body.getMaxAddress()
  get_thread_local_storage_addr = memory.findBytes(ipc_func_start, ipc_func_end, get_thread_local_storage_bytes, get_thread_local_storage_mask, True, monitor)

  ipc_store_header_addr = get_thread_local_storage_addr.add(4)
  ipc_header = None

  while ipc_header is None and ipc_store_header_addr < svc_send_sync_request_addr:
    ipc_header = getIpcHeaderFromAddr(ipc_store_header_addr)
    ipc_store_header_addr = ipc_store_header_addr.add(4)

  if ipc_header is None:
    print('Cannot find ipc header for {}!'.format(ipc_func_addr))
    continue

  handle = getHandleOfIpcCommand(ipc_func)
  nameIpcFunc(ipc_func, ipc_header, handle)
  if wrapper_func is not None:
    nameIpcWrapperFunc(wrapper_func, ipc_header, handle)

  start_address = ipc_func_addr.subtract(4)
