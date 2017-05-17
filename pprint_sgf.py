import sys

KEYWORD = "segfault"
ERRORS = {
 4 : "READ",
 6 : "WRITE", 
}

def parse_segfault_line(line):
  if " segfault at " not in line:
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
    INFO['tgt_str'] = fail_at
    INFO['tgt_lib'] = fail_file
    INFO['tgt_mem_base'], INFO['tgt_mem_size'] = [int(x,16) for x in fail_rva.split("+")]
    INFO['tgt_mem_end'] = INFO['tgt_mem_base'] +  INFO['tgt_mem_size']
    if INFO['reg_ip'] > INFO['tgt_mem_base'] and INFO['reg_ip'] < INFO['tgt_mem_end']:
      INFO['tgt_offset'] = INFO['reg_ip'] - INFO['tgt_mem_base']
    else:
      INFO['tgt_offset'] = 0
    return INFO
  except Exception as err:
    print "FAIL TO PARSE LINE, reason [ {0} ] ".format(err)
    return None

def pprint_multi(info): ## TODO : wtf on 64 bit ;P
  print """
--- BEGIN SEGFAULT ---
  PROC  : {proc_name}
  PID   : {proc_pid}
  MEM @ : 0x{mem_addr:08x}
  EIP   : 0x{reg_ip:08x}
  ESP   : 0x{reg_sp:08x}
  ECODE : {err_code} ({err_str})
  CRASH-LIB: {tgt_lib}
  CRASH-MEM: 0x{tgt_mem_base:08x} ... 0x{tgt_mem_end:08x} (+0x{tgt_mem_size:08x})
  EIP-BASE : 0x{tgt_offset:08x}
--- END SEGFAULT ---
  """.format(**info)



def pprint_single(info):
  print "PROC=[{proc_name}] PID={proc_pid} MEM=0x{mem_addr:08x} EIP=0x{reg_ip:08x} ESP=0x{reg_sp:08x} ERR={err_code} LIB=[{tgt_lib}] MEM-BLOCK=0x{tgt_mem_base:08x}...0x{tgt_mem_end:08x} ADDR=0x{tgt_offset:08x} ".format(**info)



def pprint_json(info):  
  import json
  print json.dumps(info)



def main():
  STYLE = sys.argv[1] if len(sys.argv)>1 else "multi"
  if "-h" in STYLE:
    print "USAGE:"
    print " python {0} <style> < logs.txt ".format(sys.argv[0]) 
    print 
    print "  style = { single, multi, json } "
    print 
    return 
  func = ""
  for line in sys.stdin:
    info = parse_segfault_line(line)
    if info is None:
      continue
    if STYLE == "single":
      pprint_single(info)
    if STYLE == "multi":
      pprint_multi(info)
    if STYLE == "json":
      pprint_json(info)
    

if __name__ == "__main__":
  main()

  
  
