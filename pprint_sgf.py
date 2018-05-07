import argparse
import sys
import os
import tempfile
import subprocess

KEYWORD = "segfault"
ERRORS = {
 4 : "READ",
 6 : "WRITE", 
}
CHECK_SEGFAULT_AT = True

DISASM_CACHE={}

CTX_LINES = 3

class EE(Exception):
  pass

def try_parse_binary(segfault, path_to_binary):
  global DISASM_CACHE
  import elftools.elf.elffile
  lib_name = segfault['tgt']['lib']
  full_fn = os.path.join(path_to_binary, lib_name)
  if not os.path.isfile(full_fn):
    raise Exception('{0} - file not found '.format(full_fn))
  if full_fn not in DISASM_CACHE:
    tmp = tempfile.mkstemp('-disasm')[1]
    os.system('objdump -M intel -dSlr {inp} > {out}'.format(inp=full_fn, out=tmp))
    DISASM_CACHE[full_fn] = tmp
  ext = {}
  ext['file_path'] = full_fn
  ext['disasm_line'] = ''
  ext['disasm_context'] = '' 
  search_for = '{0:x}:'.format(segfault['tgt']['offset'])
  grep_args = ['grep']
  grep_args.append('-C{0}'.format(CTX_LINES))
  grep_args.append('-e')
  grep_args.append("\s{0}\s".format(search_for))
  grep_args.append(DISASM_CACHE[full_fn])
  try:
    lines = subprocess.check_output(grep_args).strip("\n").split("\n")
    ext['disasm_context'] = lines
    for l in lines:
      if search_for in l:
        ext['disasm_line'] = l
        break
  except Exception as err:
    pass
  return ext

def unstr(hexstr):
  just = 2*4 
  if len(hexstr) > just:
    just = 2*8   
  hexstr = hexstr.rjust(just, '0')
  return ''.join(c if ord(c) >= 0x20 and ord(c) < 126 else '.' for c in hexstr.decode('hex')[::-1])


def parse_segfault_line(line, path_to_binary=None):
  if CHECK_SEGFAULT_AT and " segfault at " not in line:
    return None
  try:
    elements = line.strip().split(" ")
    pos = elements.index(KEYWORD)
    INFO = {}
    INFO['proc_name'],INFO['proc_pid'] = elements[pos-1][:-2].split("[")
    INFO['mem_addr'] = int(elements[pos+2],16)
    INFO['reg_ip'] = int(elements[pos+4],16)
    INFO['reg_sp'] = int(elements[pos+6],16)
    INFO['mem_addr_str'] = unstr(elements[pos+2])
    INFO['reg_ip_str'] = unstr(elements[pos+4])
    INFO['reg_sp_str'] = unstr(elements[pos+6])
    INFO['err_code'] = int(elements[pos+8])
    INFO['err_str'] = ERRORS.get(INFO['err_code']," ?? ")
    fail_at = elements[pos+10]
    fail_file, fail_rva = fail_at[0:-1].split("[")
    INFO['tgt'] = {}
    INFO['tgt']['str'] = fail_at
    INFO['tgt']['lib'] = fail_file
    INFO['tgt']['mem_base'], INFO['tgt']['mem_size'] = [int(x,16) for x in fail_rva.split("+")]
    INFO['tgt']['mem_end'] = INFO['tgt']['mem_base'] +  INFO['tgt']['mem_size']
    if INFO['reg_ip'] > INFO['tgt']['mem_base'] and INFO['reg_ip'] < INFO['tgt']['mem_end']:
      INFO['tgt']['offset'] = INFO['reg_ip'] - INFO['tgt']['mem_base']
    else:
      INFO['tgt']['offset'] = 0
    for key in ['mem_base','mem_end','mem_size','offset']:
      k2 = key + "_hex"
      INFO['tgt'][k2] = "0x{0:08X}".format(INFO['tgt'][key])
    INFO['binary'] = None
    if path_to_binary is not None:
      try:
        INFO['binary'] = try_parse_binary(INFO, path_to_binary)
      except Exception as err:
        print("Fail to parse binary, reason: {0}".format(err))
    return INFO
  except Exception as err:
    print("FAIL TO PARSE LINE, reason: {0}".format(err))
    return None

def pprint_multi(info): ## TODO : wtf on 64 bit ;P
  bin_info = ''  
  if info['binary'] is not None:
    bin_info = """    
  >> BINARY
    FILE PATH : {binary[file_path]}
    LINE : [ {binary[disasm_line]} ]
    -- disasm -- 8< --
{lines}
    -- disasm -- 8< --   
  << BINARY  
""".format(lines='\n'.join(info['binary']['disasm_context']),**info)

  print("""
>> BEGIN
  PROC  : {proc_name}
  PID   : {proc_pid}
  MEM @ : 0x{mem_addr:016x}  [{mem_addr_str}]
  EIP   : 0x{reg_ip:016x}  [{reg_ip_str}]
  ESP   : 0x{reg_sp:016x}  [{reg_sp_str}]
  ECODE : {err_code} ({err_str})
  CRASH-LIB: {tgt[lib]}
  CRASH-MEM: 0x{tgt[mem_base]:016x} ... 0x{tgt[mem_end]:016x} (size 0x{tgt[mem_size]:016x})
  EIP-BASE : 0x{tgt[offset]:016x}  == EIP - BASE
{bin_info}
<< SEGFAULT
  """.format(bin_info=bin_info, **info))


def pprint_single(info):
  bin_info=''
  if info['binary'] is not None:
    bin_info = 'FILE={binary[file_path]}; LINE={binary[disasm_line]}'.format(**info)
  print("PROC=[{proc_name}] PID={proc_pid} MEM=0x{mem_addr:08x} EIP=0x{reg_ip:08x} ESP=0x{reg_sp:08x} ERR={err_code} LIB=[{tgt[lib]}] MEM-BLOCK=0x{tgt[mem_base]:08x}...0x{tgt[mem_end]:08x} ADDR=0x{tgt[offset]:08x} BIN_INFO=[{bin_info}]".format(bin_info=bin_info, **info))


def pprint_json(info):  
  import json
  print(json.dumps(info))

FORMATTERS = {
  "json" : pprint_json,
  "single" : pprint_single,
  "multi" : pprint_multi,
}

FORMATTER_DEFAULT = "multi"

def is_matching_line(line, array_of_str):
  for s in array_of_str:
    if s not in line:
      return False
  return True

def main():

  fmt_opts = ",".join(FORMATTERS.keys())
  parser = argparse.ArgumentParser(description='Segfault Parser')
  parser.add_argument('--logfile',action="store",  help="Path to log (dmesg?) file", required=True)
  parser.add_argument('--format', action="store",  help="Output format, can be [{0}], default = {1}".format(fmt_opts, FORMATTER_DEFAULT), default=FORMATTER_DEFAULT)
  parser.add_argument('--grep',   action="append", help="Look for lines containing this string. Can use multiple times.")
  parser.add_argument('--bins',   action="store",  help="Path to directory containing binaries && libs. Default=None. If specified, script will try to find binary that caused fault (by name) and parse it", default=None)
  parser.add_argument('--count',  action="store",  help="Exit after X parsed entries (like head ;)", default=-1, type=int)
  parsed_args = parser.parse_args()

  file_handle = open(parsed_args.logfile,'r')
  func = FORMATTERS.get(parsed_args.format, None)
  if func is None or not callable(func):
    print("Invalid argument: output format")
    return 1
  
  count = 0
  for line in file_handle:
    if parsed_args.grep is not None and len(parsed_args.grep)>0:
      # this way you don't need to pipe-grep-pipe
      if not is_matching_line(line, parsed_args.grep):
        continue
    info = parse_segfault_line(line, parsed_args.bins)
    if info is not None:
      func(info)
    count += 1
    if parsed_args.count > 0 and count >= parsed_args.count:
      return

  
if __name__ == "__main__":
  main()
  for f in DISASM_CACHE: # clear cache ... 
    v = DISASM_CACHE[f]
    # print "Delete " + v
    os.remove(v)


  
