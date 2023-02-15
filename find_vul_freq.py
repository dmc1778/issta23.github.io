
import pandas as pd
import re, csv
from csv import writer


REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC_FLAWFINDER = re.compile('\:(\d+)\:')
REG_RATS = re.compile('<vulnerability>')
REG_CPP_CHECK_LOC = re.compile('line=\"(\d+)\"')
REG_CPP_CHECK = re.compile('error id=')

FIND_CWE_IDENTIFIER = re.compile('CWE-(\d+)')
FIND_RATS_VUL_TYPE = re.compile('<type.*>((.|\n)*?)<\/type>')
REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC_INFER = re.compile("(\d+)\:\serror\:")
REG_LOC_CLANG = re.compile("((\d+)\:(\d+)\:)")
REG_VUL_TYPE_INFER = re.compile("error\:(.*)")
REG_VUL_TYPE_CLANG = re.compile("((\d+)\:(\d+)\:(.*))")
REGEX_INFER = re.compile("error\:((.|\n)*?)\\\\n")

def decompose_detections(splitted_lines, detector_name):
    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if detector_name == 'flawfinder':
            if REG_LOC_FLAWFINDER.search(splitted_lines[j]):
                indices.append(j)
            j += 1
        if detector_name == 'cppcheck':
            if REG_CPP_CHECK.search(splitted_lines[j]):
                indices.append(j)
            j += 1

    if len(indices) == 1:
        for i, item in enumerate(splitted_lines):
            if i != 0:
                super_temp.append(item)
        super_temp = [super_temp]
    else:
        i = 0
        j = 1
        while True:
            temp = [] 
            for row in range(indices[i], indices[j]):
                temp.append(splitted_lines[row])
            super_temp.append(temp)
            if j == len(indices)-1:
                temp = [] 
                for row in range(indices[j], len(splitted_lines)):
                    temp.append(splitted_lines[row])
                super_temp.append(temp)
                break
            i+= 1
            j+= 1

    return super_temp

class Dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)
        
def find_regex_groups(warning):
    cwe_list = []
    # v = '\\n'.join(warning)
    if re.findall(r'CWE-(\d+)', warning):
        x = re.findall(r'CWE-(\d+)', warning)
    for cwe_ in x:
        cwe_list.append('CWE-'+cwe_)
    return cwe_list

def find_cppcheck_cwe(warning):
    cwe_list = []
    # v = '\\n'.join(warning)
    if re.findall(r'cwe=\"(\d+)\"', warning):
        x = re.findall(r'cwe=\"(\d+)\"', warning)
        for cwe_ in x:
            cwe_list.append('CWE-'+cwe_)
    return cwe_list

def find_rat_types(warning):
    if re.findall(r'<type.*>((.|\n)*?)<\/type>', warning):
        x = list(re.findall(r'<type.*>((.|\n)*?)<\/type>', warning)[0])
        del x[-1]
    if re.findall(r'resulting in a\s(.*?)\.', warning):
        x = re.findall(r'resulting in a\s(.*?)\.', warning)
    return x

def parse_flawfinder(output):
    cwe_final_list = []
    if not isinstance(output, float):
        if REG_LOC_FLAWFINDER.search(output):
            cwe_list = find_regex_groups(output)
            for cwe in cwe_list:
                cwe_final_list.append(cwe)
        return cwe_final_list
    else:
        return None
        

def parse_rats(output):
  cwe_final_list = []
  if re.findall(r'<line.*>((.|\n)*?)<\/line>', output):
    cwe_list = find_rat_types(output)
    for cwe in cwe_list:
      cwe_final_list = cwe_final_list + [cwe]
  return cwe_final_list

def parse_cppcheck(output):
    cwe_final_list = []
    if REG_CPP_CHECK_LOC.search(output):
        cwe_list = find_cppcheck_cwe(output)
        for cwe in cwe_list:
            cwe_final_list = cwe_final_list + [cwe]
            
        return cwe_final_list

def parse_infer(output):
    cwe_final_list = []

    if REG_LOC_INFER.search(output):
        x = int(REG_LOC_INFER.search(output).group(1))
        cwe_final_list = cwe_final_list + [REG_VUL_TYPE_INFER.search(output).group(1)]

        return cwe_final_list

def parse_clang(output):
    cwe_final_list = []
    if re.findall(r"((\d+)\:(\d+)\:\swarning\:(.*))", output) or re.findall(r"((\d+)\:(\d+)\:\serror\:(.*))", output):
        if REG_LOC_CLANG.search(output):
            x = int(REG_LOC_CLANG.search(output).group(2))
            cwe_final_list = cwe_final_list + [
                        REG_VUL_TYPE_CLANG.search(output).group(4)
                    ]
        return cwe_final_list
    
data_addr = 'warnings.csv'

data = pd.read_csv(data_addr, sep=',', encoding='utf-8')

warning_holder = []
all_cwe = []
for idx, row in data.iterrows():
  warning_holder.append(row['Warning1'])
  warning_holder.append(row['Warning2'])
  warning_holder.append(row['Warning3'])
  warning_holder.append(row['Warning4'])
  warning_holder.append(row['Warning5'])

  if row['Tool'] == 'flawfinder':
    for w in warning_holder:
      if w!='None':
        out = parse_flawfinder(w)
        if out is not None:
            for war in out:
                all_cwe.append(['flawfinder',war])
                
  elif row['Tool'] == 'rats':
    for w in warning_holder:
      if w!='None':
        out = parse_rats(w)
        for war in out:
            all_cwe.append(['rats',war])
            
  elif row['Tool'] == 'cppcheck':
    for w in warning_holder:
      if w!='None':
        out = parse_cppcheck(w)
        for war in out:
            all_cwe.append(['cppcheck',war])
            
  elif row['Tool'] == 'infer':
    for w in warning_holder:
      if w!='None':
        out = parse_infer(w)
        if out is not None:
            for war in out:
                all_cwe.append(['infer' ,war])
                
  else:
      continue
  
  warning_holder= []
      