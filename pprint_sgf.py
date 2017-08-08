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
    return '{0} - file not found '.format(full_fn)
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
  MEM @ : 0x{mem_addr:08x}
  EIP   : 0x{reg_ip:08x}
  ESP   : 0x{reg_sp:08x}
  ECODE : {err_code} ({err_str})
  CRASH-LIB: {tgt[lib]}
  CRASH-MEM: 0x{tgt[mem_base]:08x} ... 0x{tgt[mem_end]:08x} (size 0x{tgt[mem_size]:08x})
  EIP-BASE : 0x{tgt[offset]:08x}  == EIP - BASE
{bin_info}
<< SEGFAULT
  """.format(bin_info=bin_info, **info))


def pprint_single(info):
  bin_info=''
  if info['binary'] is not None:
    bin_info = 'FILE={binary[file_path]}; LINE={binary[disasm_line]}'.format(**info)
  print "PROC=[{proc_name}] PID={proc_pid} MEM=0x{mem_addr:08x} EIP=0x{reg_ip:08x} ESP=0x{reg_sp:08x} ERR={err_code} LIB=[{tgt[lib]}] MEM-BLOCK=0x{tgt[mem_base]:08x}...0x{tgt[mem_end]:08x} ADDR=0x{tgt[offset]:08x} BIN_INFO=[{bin_info}]".format(bin_info=bin_info, **info)



def pprint_json(info):  
  import json
  print json.dumps(info)


def is_good_line(line, array_of_str):
  for s in array_of_str:
    if s not in line:
      return False
  return True

def main():

  parser = argparse.ArgumentParser(description='Segfault Parser')
  parser.add_argument('--format', action="store", default="single", help="Output format, can be {singlie,multi,json}")
  parser.add_argument('--logfile',action="store", help="log file", required=True)
  parser.add_argument('--grep',   action="append", help="Look for lines containing this string. Can use multiple times.")
  parser.add_argument('--binary', action="store", help="Path to directory containing binaries && libs.", default=None)
  parser.add_argument('--count',  action="store", help="Exit after X parsed entries", default=-1, type=int)
  results = parser.parse_args()

  fh = open(results.logfile,'r')
  func = None
  if results.format == 'single':
    func = pprint_single
  if results.format == 'multi':
    func = pprint_multi
  if results.format == 'json':
    func = pprint_json 
  
  count = 0
  for line in fh:
    if len(results.grep)>0:
      if not is_good_line(line, results.grep):
        continue
    info = parse_segfault_line(line, results.binary)
    func(info)
    count += 1
    if results.count > 0 and count >= results.count:
      return

  

if __name__ == "__main__":
  main()
  for f in DISASM_CACHE: # clear cache ... 
    v = DISASM_CACHE[f]
    # print "Delete " + v
    os.remove(v)


  
