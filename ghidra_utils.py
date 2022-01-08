# Gross, but seems to be the way to get the ghidra apis/values from an external module
from __main__ import currentProgram, monitor
from array import array
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompInterface

flatProgramAPI = FlatProgramAPI(currentProgram)
toAddr = flatProgramAPI.toAddr
getFunctionContaining = flatProgramAPI.getFunctionContaining
getNamespace = flatProgramAPI.getNamespace

memory = currentProgram.getMemory()
symbolTable = currentProgram.getSymbolTable()
namespaceManager = currentProgram.getNamespaceManager()
globalNamespace = namespaceManager.getGlobalNamespace()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

def bytesToByteStr(bytes):
  encoded_bytes = map(lambda byte : chr(byte), bytes)
  return ''.join(encoded_bytes)

def bytesToByteArr(bytes):
  return array('b', bytesToByteStr(bytes))

def findByteArray(bytes, mask = None):
  result = []
  addr = toAddr(0)
  byte_arr = bytesToByteArr(bytes)

  mask_arr = None
  if mask is not None:
    mask_arr = bytesToByteArr(mask)

  while True:
    addr = memory.findBytes(addr.add(len(bytes)), byte_arr, mask_arr, True, monitor)
    if addr is not None:
      result.append(addr)
    else:
      return result

def findFirstByteArray(bytes, mask = None):
  byte_arr = bytesToByteArr(bytes)
  mask_arr = None
  if mask is not None:
    mask_arr = bytesToByteArr(mask)
  return memory.findBytes(toAddr(0), byte_arr, mask_arr, True, monitor)

def readBytes(addr, len):
  byteArray = bytesToByteArr([0 for i in range(len)])
  memory.getBytes(addr, byteArray)
  return byteArray

def forceSetVariableName(variable, name):
  while True:
    try:
      variable.setName(name, SourceType.USER_DEFINED)
      break
    except:
      name = '_' + name
  return name

def decompileContainingFunction(addr):
  func = getFunctionContaining(addr)
  return decomp.decompileFunction(func, 60, monitor), func

def getOrCreateNamespace(namespace_name, parent_namespace = globalNamespace):
    namespace = getNamespace(parent_namespace, namespace_name)

    if namespace is not None:
        return namespace

    return symbolTable.createNameSpace(parent_namespace, namespace_name, SourceType.USER_DEFINED)

def getOrCreateNestedNamespace(str, parent_namespace):
  namespaces = str.split('::')
  current_parent = parent_namespace

  for namespace in namespaces:
    if len(namespace) > 0:
      current_parent = getOrCreateNamespace(namespace, current_parent)

  return current_parent

def nameCtrFunc(func, name):
  split_name = name.split('::')
  base_name = split_name[-1]

  namespace = '::'.join(split_name[:-1])
  ctr_namespace = getOrCreateNamespace('ctr')
  func_namespace = getOrCreateNestedNamespace(namespace, ctr_namespace)

  func.setName(base_name, SourceType.USER_DEFINED)
  func.setParentNamespace(func_namespace)
  print('Named {} to {}'.format(func.getEntryPoint(), base_name))

def getCallArgs(caller_func, callee_addr):
    decompiled_func = decomp.decompileFunction(caller_func, 60, monitor)
    high_func = decompiled_func.getHighFunction()

    if not high_func:
      return []

    opiter = high_func.getPcodeOps()
    while opiter.hasNext():
      op = opiter.next()
      mnemonic = str(op.getMnemonic())
      if mnemonic == 'CALL':
        inputs = op.getInputs()
        addr = inputs[0].getAddress()
        if addr == callee_addr:
          return inputs[1:]

    return []

def getCallArgsFromRef(call_ref):
    from_addr = call_ref.getFromAddress()
    to_addr = call_ref.getToAddress()
    func = getFunctionContaining(from_addr)
    return getCallArgs(func, to_addr)

def getValueFromConstantVarnode(varnode):
  addr = varnode.getAddress()
  if addr.isConstantAddress():
    return addr.getOffset()
  return None
