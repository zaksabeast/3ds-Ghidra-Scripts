# Set thread local storage types
# @category 3ds
#

from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode.HighFunctionDBUtil import commitLocalNamesToDatabase
from ghidra_utils import findByteArray, forceSetVariableName, decompileContainingFunction, nameCtrFunc

tls_struct = """
struct ThreadLocalStorage {
    uint storage[32];
    uint command_buffer[64];
    uint static_buffers[32];
};
"""

# Add the ThreadLocalStorage and PThreadLocalStorage types
data_type_manager = currentProgram.getDataTypeManager()
parser = CParser(data_type_manager)
parsed_datatype = parser.parse(tls_struct)
data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
parsed_datatype = parser.parse('typedef ThreadLocalStorage *PThreadLocalStorage;')
tls_pointer_datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)

# Handle inlined getThreadLocalStorage
get_tls_bytes = [0x70, 0x4f, 0x1d, 0xee]
get_tls_mask = [0xff, 0x0f, 0xff, 0xff]
tls_addrs = findByteArray(get_tls_bytes, get_tls_mask)

for tls_addr in tls_addrs:
  decompiled_func, _ = decompileContainingFunction(tls_addr)
  high_func = decompiled_func.getHighFunction()
  commitLocalNamesToDatabase(high_func, SourceType.USER_DEFINED)

  # Refresh high func after committing local names
  decompiled_func, func = decompileContainingFunction(tls_addr)
  high_func = decompiled_func.getHighFunction()

  tls_symbol = None
  lsm = high_func.getLocalSymbolMap()
  high_symbols = lsm.getSymbols()
  for high_symbol in high_symbols:
    if high_symbol.getPCAddress() == tls_addr:
      tls_symbol = high_symbol.getSymbol()
      break

  if tls_symbol is not None:
    variables = func.getLocalVariables()
    for variable in variables:
      if tls_symbol == variable.getSymbol():
        variable.setDataType(tls_pointer_datatype, SourceType.USER_DEFINED)
        forceSetVariableName(variable, 'tls')
        print('Retyped {} and set name to {}'.format(tls_addr, variable.getName()))
        break


# Handle getThreadLocalStorage when not inlined
get_tls_bytes = [0x70, 0x4f, 0x1d, 0xee, 0x1e, 0xff, 0x2f ,0xe1]
get_tls_mask = [0xff, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
tls_addrs = findByteArray(get_tls_bytes, get_tls_mask)

for tls_addr in tls_addrs:
  func = getFunctionContaining(tls_addr)
  nameCtrFunc(func, 'getThreadLocalStorage')
