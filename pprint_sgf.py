import argparse
import sys
import os
import tempfile
import subprocess
import yaml

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

class HexInt(int): pass

def try_parse_binary(info, path_to_binary):
  global DISASM_CACHE
  DISASM_SUFIX="-disasm"
  import elftools.elf.elffile
  ext = {}
  lib_name = info['fail']['binary']
  full_fn = os.path.join(path_to_binary, lib_name)
  if not os.path.isfile(full_fn):
    raise Exception('{0} - file not found '.format(full_fn))
  if full_fn not in DISASM_CACHE:
    tmp = tempfile.mkstemp(DISASM_SUFIX)[1]
    objdump_cmd = 'objdump -M intel -dlr {inp} > {out}'.format(inp=full_fn, out=tmp)
    os.system(objdump_cmd)
    DISASM_CACHE[full_fn] = tmp
    ext['_objdump'] = objdump_cmd
  ext['file_path'] = full_fn
  ext['_tmp_path'] = DISASM_CACHE[full_fn]
  ext['disasm_line'] = ''
  ext['disasm_context'] = '' 
  look_for = '{0:x}:\t'.format(info["fail"]["binary_offset"])
  ext['_loog_for'] = look_for
  grep_args = ['grep']
  grep_args.append('-C{0}'.format(CTX_LINES))
  grep_args.append('-e')
  grep_args.append(look_for)
  grep_args.append(DISASM_CACHE[full_fn])
  try:
    lines = subprocess.check_output(grep_args).strip("\n").split("\n")
    #print(lines)
    ext['disasm_context'] = lines
    ext['disasm_line'] = lines[CTX_LINES]
  except Exception as err:
    ext['_grep_fail'] = str(err)
  return ext

def unstr(hexstr):
  just = 2*4 
  if len(hexstr) > just:
    just = 2*8   
  hexstr = hexstr.rjust(just, '0')
  return ''.join(c if ord(c) >= 0x20 and ord(c) < 126 else '.' for c in hexstr.decode('hex')[::-1])

# deadbeef ip 0000000000400558 sp 00007ffce3073ee0 error 4 in segf.o[400000+1000]
FIELDS = [ "process", "__seg", "__at", "mem_addr","__ip","reg_ip","__sp","reg_sp","__er","error_code","__in","fail_org" ]

def parse_segfault_line(line):
  if CHECK_SEGFAULT_AT and " segfault at " not in line:
    raise EXception("no 'segfault at' in line !")
  #line = line.split("segfault at",1)[1] # cut useless stuff

  elements = line.strip().split(" ")
  keyword_pos = elements.index(KEYWORD)
  elements = elements[keyword_pos-1:]
  info = dict(zip(FIELDS, elements))
  for key in info.keys():
    if key.startswith("__"):
      del info[key]

  info['process_name'], info['process_pid'] = info['process'][:-2].split("[",1)

  for key in ['mem_addr', 'reg_ip', 'reg_sp']:
    info['{0}_str'.format(key)] = unstr(info[key])
    info[key] = HexInt(info[key], 16)
  
  info['error_str'] = ERRORS.get(info['error_code'], "<unknown code>")
  fail_file, fail_rva = info['fail_org'][:-1].split("[")
  fail_base, fail_size = [HexInt(x,16) for x in fail_rva.split("+",1)]
  
  eip = info['reg_ip']
  fail_offset = 0
  if eip > fail_base and eip < fail_base + fail_size:
    fail_offset = eip - fail_base
    
  info['fail'] = dict(
    binary = fail_file,
    mem_base = fail_base,
    mem_size = fail_size,
    mem_end = HexInt(fail_base + fail_size),
    binary_offset = HexInt(fail_offset),
  )
  # print(pprint_yaml(info))
  return info



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
  PROC  : {process_name}
  PID   : {process_pid}
  MEM @ : 0x{mem_addr:016x}  [{mem_addr_str}]
  EIP   : 0x{reg_ip:016x}  [{reg_ip_str}]
  ESP   : 0x{reg_sp:016x}  [{reg_sp_str}]
  ECODE : {error_code} ({error_str})
  CRASH-LIB: {fail[binary]}
  CRASH-MEM: 0x{fail[mem_base]:016x} ... 0x{fail[mem_end]:016x} (size 0x{fail[mem_size]:016x})
  EIP-BASE : 0x{fail[binary_offset]:016x}  == EIP - BASE
{bin_info}
<< SEGFAULT
  """.format(bin_info=bin_info, **info))


def pprint_single(info):
  tpl = [
    "PROC=[{process_name}]",
    "PID={process_pid}",
    "MEM=0x{mem_addr:08x}",
    "EIP=0x{reg_ip:08x}",
    "ESP=0x{reg_sp:08x}",
    "ERR={error_code}",
    "LIB=[{fail[binary]}]",
    "MEM-BLOCK=0x{fail[mem_base]:08x}...0x{fail[mem_end]:08x}",
    "ADDR=0x{fail[binary_offset]:08x}",
  ]
  if info['binary'] is not None:
    tpl.append('BIN_FILE={binary[file_path]}')
    tpl.append('BIN_LINE=[[{binary[disasm_line]}]]')

  print(" ".join(tpl).format(**info))

def pprint_yaml(info):  
  def _hexint_str(dumper, data):
    return yaml.ScalarNode('tag:yaml.org,2002:int', "0x{0:016X}".format(data))
  yaml.add_representer(HexInt, _hexint_str)
  print(yaml.dump(info,default_flow_style=False))

def pprint_json(info):  
  import json
  print(json.dumps(info))

FORMATTERS = {
  "json" : pprint_json,
  "single" : pprint_single,
  "multi" : pprint_multi,
  "yaml"  : pprint_yaml,
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
  parser.add_argument('--logfile',action="store",  help="Path to log (dmesg?) file. '-' for STDIN.", required=True)
  parser.add_argument('--format', action="store",  help="Output format, can be [{0}], default = {1}".format(fmt_opts, FORMATTER_DEFAULT), default=FORMATTER_DEFAULT)
  parser.add_argument('--grep',   action="append", help="Look for lines containing this string. Can use multiple times.")
  parser.add_argument('--bins',   action="store",  help="Path to directory containing binaries && libs. Default=None. If specified, script will try to find binary that caused fault (by name) and parse it", default=None)
  parser.add_argument('--count',  action="store",  help="Exit after X parsed entries (like head ;)", default=-1, type=int)
  parsed_args = parser.parse_args()

  file_handle = None
  if parsed_args.logfile == '-':
    file_handle = sys.stdin
  else:  
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

    info = None
    try:
      info = parse_segfault_line(line)
    except:
      pritn("<parsing failed?>")
      continue
    info['binary'] = None  
    if  parsed_args.bins:
      
      try:
        info['binary'] = try_parse_binary(info, parsed_args.bins)
      except:
        pass

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


  
