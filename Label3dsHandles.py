# Labels 3ds CTR lib handles
# @category 3ds
#

from ghidra.program.model.symbol import SourceType
from ghidra_utils import getOrCreateNamespace, getCallArgsFromRef
from ctr_services import getServiceHandleName, getServiceCallerRefs

memory = currentProgram.getMemory()

# Find service refs
service_caller_refs = getServiceCallerRefs()

# Find service handles
ctr_namespace = getOrCreateNamespace('ctr')
srv_namespace = getOrCreateNamespace('srv', ctr_namespace)
possible_get_service_handle_direct_symbols = getSymbols('GetServiceHandleDirect', srv_namespace)

if len(possible_get_service_handle_direct_symbols) == 0:
  raise Exception('Cannot find ctr::srv::GetServiceHandleDirect.  Please find and label it!')

if len(possible_get_service_handle_direct_symbols) > 1:
  raise Exception('More than one ctr::srv::GetServiceHandleDirect symbols.  This script can only run if one exists!')

get_service_handle_direct = getSymbols('GetServiceHandleDirect', srv_namespace)[0]
get_handle_refs = getReferencesTo(get_service_handle_direct.getAddress())

service_handles = {}

for get_handle_ref in get_handle_refs:
  addr = get_handle_ref.getFromAddress()
  args = getCallArgsFromRef(get_handle_ref)
  if len(args) < 2:
    print('Bad number of args at {}'.format(addr))
    continue
  handle_ref = args[0]
  service = args[1]
  if handle_ref.isAddress():
    handle_addr = memory.getInt(handle_ref.getAddress())
    handle = toAddr(handle_addr)
    caller_func = getFunctionContaining(addr)
    if caller_func is not None:
      caller_addr = caller_func.getEntryPoint()
      service = service_caller_refs[caller_addr]
      service_handles[service] = handle
      label = getServiceHandleName(service)
      createLabel(handle, label, ctr_namespace, True, SourceType.USER_DEFINED)
      print('Created handle {} at {}'.format(label, handle))
  else:
    # TODO: This might be improved with pcode
    print('Unable to detect handle name at {}'.format(addr))
