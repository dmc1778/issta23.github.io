import os, re, subprocess, json
from pydriller import GitRepository as PyDrillerGitRepo
from csv import writer
import csv
import time, codecs
from subprocess import run
import pandas as pd
from git import Repo

user_names = ['mlpack', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']

_extensions = ['cc', 'cpp', 'hpp', 'h', 'c', 'cu']

this_project = os.getcwd()

REG_CHANGED = re.compile(".*@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*")
REG_LOC_INFER = re.compile('(\d+)\:\serror\:')
REG_LOC_CLANG = re.compile('((\d+)\:(\d+)\:)')
REG_VUL_TYPE_INFER = re.compile('error\:(.*)')
REG_VUL_TYPE_CLANG = re.compile('((\d+)\:(\d+)\:(.*))')


class Dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)

def decompose_detections(splitted_lines, detector_name):
    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if detector_name == 'infer':
            if REG_LOC_INFER.search(splitted_lines[j]):
                indices.append(j)
            j += 1
        if detector_name == 'clang':
            if REG_LOC_CLANG.search(splitted_lines[j]):
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


def get_patches(splitted_lines):
    change_info = {}
    i = 0
    for line in splitted_lines:
        if REG_CHANGED.match(line):
            i += 1
            addStart = int(REG_CHANGED.search(line).group(1))
            addedLines = int(REG_CHANGED.search(line).group(2))
            deletedStart = int(REG_CHANGED.search(line).group(3))
            deletedLines = int(REG_CHANGED.search(line).group(4))
                        
            start = deletedStart
            if(start == 0):
                start += 1
    
            end = addStart+addedLines-1
            change_info[i] = [deletedStart, deletedStart+deletedLines]

    super_temp = []
    j = 0
    indices = []
    while j < len(splitted_lines):
        if re.findall(r'(@@)',splitted_lines[j]):
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
            for row in range(indices[i]+1, indices[j]):
                temp.append(splitted_lines[row])
            super_temp.append(temp)
            if j == len(indices)-1:
                temp = [] 
                for row in range(indices[j]+1, len(splitted_lines)):
                    temp.append(splitted_lines[row])
                super_temp.append(temp)
                break
            i+= 1
            j+= 1
    return super_temp, change_info



def get_diff_header(diff):
    code_lines = diff.split('\n')
    [super_temp, change_info] = get_patches(code_lines)
    return change_info


def get_fix_file_names(commit):
    f_names = {}
    raw_name = []
    if 'test' not in commit.filename:
        diff_split = get_diff_header(commit.diff)
        if bool(commit.new_path):
            f_names[commit.new_path] = diff_split
            raw_name.append(commit.new_path)
        else:
            f_names[commit.old_path] = diff_split
            raw_name.append(commit.old_path)
    else:
        if 'test' not in commit.filename:
            diff_split = get_diff_header(commit.diff)
            if bool(commit.new_path):
                f_names[commit.new_path] = diff_split
                raw_name.append(commit.new_path)
            else:
                f_names[commit.old_path] = diff_split
                raw_name.append(commit.old_path)
    return f_names, raw_name

def get_prev_file_names(repository_path, items):
    f_names = {}
    for k, value in items.items():
        for item in value:
            for prev_commit in item['previous_commits']:
                x = PyDrillerGitRepo(repository_path).get_commit(prev_commit[0])
                for modification in x.modifications:
                    if 'test' not in modification.filename:
                        diff_split = get_diff_header(modification.diff)
                        if bool(modification.new_path):
                            f_names[modification.new_path] = diff_split
                        else:
                            f_names[modification.old_path] = diff_split
    return f_names

def parse_clang(output):
    cwe_final_list = []
    parsed_output = Dictlist()
    if re.findall(r'((\d+)\:(\d+)\:\swarning\:(.*))', output):
        detections = decompose_detections(output.split('\n'), 'clang')
        for detection in detections:
            for line in detection:
                if REG_LOC_CLANG.search(line):
                    x = int(REG_LOC_CLANG.search(line).group(2))
                    cwe_final_list = cwe_final_list + [REG_VUL_TYPE_CLANG.search(line).group(4)]            
            parsed_output[x] = '\\n'.join(detection)

        return [parsed_output, cwe_final_list]
    else:
        return 'not detected'

def parse_infer(output):
    cwe_final_list = []
    parsed_output = Dictlist()

    if re.findall(r'(No\sissues\sfound)', output):
        return 'not detected'
    elif re.findall(r'(\d+)\:\serror\:', output):
        detections = decompose_detections(output.split('\n'), 'infer')
        for detection in detections:
            for line in detection:
                if REG_LOC_INFER.search(line):
                    x = int(REG_LOC_INFER.search(line).group(1))
                    cwe_final_list = cwe_final_list + [REG_VUL_TYPE_INFER.search(line).group(1)]
                    break
            parsed_output[x] = '\\n'.join(detection)

        # for k, v in parsed_output.items():
        #     cwe_list = REG_VUL_TYPE_INFER.search(v[0]).group(1)
        #     for cwe in cwe_list:
        #         cwe_final_list = cwe_final_list + [cwe]

        return [parsed_output, cwe_final_list]
    else:
        return 'compilation error'

def find_regex_groups(warning):
    cwe_list = []
    v = '\\n'.join(warning)
    if re.findall(r'CWE-(\d+)', v):
        x = re.findall(r'CWE-(\d+)', v)
    for cwe_ in x:
        cwe_list.append('CWE-'+cwe_)
    return cwe_list

def remove_white_spaces(split_row):
    return list(filter(None, split_row))

def build_global_compile_option(compile_options, test_file, library_name):
    find_opt = False
    output = []
    with open(this_project+'/compilation_database/compile_commands_'+library_name+'.json', encoding='utf-8') as f:
        compile_options = json.loads(f.read(), strict=False)

    if library_name == 'tensorflow':
        for opt in compile_options:
            split_row = opt['command'].split(' ')
            for j, line in enumerate(list(split_row)):
                if line == '-c':
                    f_path = split_row[j+1].split('/')[0:-1]
            if f_path[0] == 'tensorflow' or f_path[0] == 'third_party':
                new_opt = '/'.join(f_path)
                if re.findall(r'(\/'+test_file.split('/')[-2]+')', new_opt):
                    output.append(opt)
                    break
                if re.findall(r'(\/'+test_file.split('/')[-3]+r'\/'+test_file.split('/')[-2]+')', new_opt):
                    output.append(opt)
                    break
                if re.findall(r'(\/'+test_file.split('/')[0]+r'\/'+test_file.split('/')[1]+')', new_opt):
                    output.append(opt)
                    break

    else:
        for opt in compile_options:
            split_opt = opt['file'].split('/')[0:-1]
            new_opt = '/'.join(split_opt)
            if re.findall(r'(\/'+test_file.split('/')[-2]+')', new_opt):
                output.append(opt)
                break
            if re.findall(r'(\/'+test_file.split('/')[-3]+r'\/'+test_file.split('/')[-2]+')', new_opt):
                output.append(opt)
                break
            if re.findall(r'(\/'+test_file.split('/')[0]+r'\/'+test_file.split('/')[1]+')', new_opt):
                output.append(opt)
                break
    return output
                

def search_for_compile_command(test_file, library_name):
    find_opt = False
    output = []
    with open(this_project+'/compilation_database/compile_commands_'+library_name+'.json', encoding='utf-8') as f:
        compile_options = json.loads(f.read(), strict=False)

    if library_name == 'tensorflow':
        for opt in compile_options:
            split_row = opt['command'].split(' ')
            for j, line in enumerate(list(split_row)):
                if line == '-c':
                    f_path = split_row[j+1].split('/')
            if f_path[0] == 'tensorflow' or f_path[0] == 'third_party':
                if os.path.join(f_path[-2], f_path[-1]) == os.path.join(test_file.split('/')[-2], test_file.split('/')[-1]):
                    find_opt = True
                    output.append(opt)
                    break
        
    else:
        for opt in compile_options:
            if os.path.join(opt['file'].split('/')[-2], opt['file'].split('/')[-1]) == os.path.join(test_file.split('/')[-2], test_file.split('/')[-1]):
                find_opt = True
                output.append(opt)
                break
    if find_opt:
        return output
    else:
        glob_compile_option = build_global_compile_option(compile_options, test_file, library_name)
        if bool(glob_compile_option):
            return glob_compile_option
        else:
            return False

def run(library_name, opt, filename, full_check, detector_name):
    # command_capture = f'infer --keep-going -- gcc {compile_options} -c '
    # command_analyze = f'infer analyze -- gcc {compile_options} -c '

    if library_name == 'tensorflow':
        split_row = opt['command'].split(' ')
        split_row = remove_white_spaces(split_row)
        split_row.remove(split_row[0])
        split_row.remove(split_row[-1])
        split_row.remove(split_row[-1])
        split_row.remove(split_row[-1])

        command_ = ' '.join(split_row)

        command_ = command_.replace("'", '')

        if full_check and detector_name == 'clang':
            new_cc = []
            
            split_row = opt['command'].split(' ')
            split_row = remove_white_spaces(split_row)
            split_row.remove(split_row[0])
            split_row.remove(split_row[-1])
            split_row.remove(split_row[-1])
            temp_path = split_row[-1]
            split_row.remove(split_row[-1])
            for j, line in enumerate(split_row):
                if 'isystem' in line:
                    new_cc.append('-isystem '+split_row[j+1])
                if 'iquote' in line:
                    new_cc.append('-iquote '+split_row[j+1])
            new_cc.append('-c')
            command_ = ' '.join(new_cc)

            _path = os.path.join(this_project,'ml_repos_cloned', library_name, temp_path)

            # command = 'clang++-10 --analyze -Xanalyzer -analyzer-output=text '+command_+' '+_path
            command = 'clang-tidy '+_path+' -checks=-*,clang-analyzer-* -- '+command_
            start_time = time.time()
            output = subprocess.getoutput(command)
            execution_time = time.time() - start_time
            
            subprocess.call('rm -rf *.plist', shell=True)
            return output, execution_time

        if full_check and detector_name == 'infer':
            command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe --starvation --racerd --pulse --loop-hoisting --biabduction -- gcc '+command_+' '+filename
            command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_+' '+filename
        else:                           
            command_capture = 'infer --keep-going -- gcc '+command_+' '+filename
            command_analyze = 'infer analyze -- gcc '+command_+' '+filename

        os.chdir(this_project)

        start_time = time.time()
        subprocess.call(command_capture, shell=True)
        output = subprocess.getoutput(command_analyze)
        execution_time = time.time() - start_time

        subprocess.call('rm -rf infer-out', shell=True)
        subprocess.call('rm -rf *.o', shell=True)
 
    else:
        split_row = opt['command'].split(' ')
        if library_name == 'numpy' or library_name == 'pandas-dev' or library_name == 'scipy':
            try:
                os.chdir(this_project)

                if full_check and detector_name == 'clang':

                    if library_name == 'pandas-dev':
                        _path = os.path.join(this_project,'ml_repos_cloned', library_name, 'pandas', '/'.join(opt['file'].split('/')))
                    else:
                        _path = os.path.join(this_project,'ml_repos_cloned', library_name,library_name, '/'.join(opt['file'].split('/')))
                    
                    split_row = remove_white_spaces(split_row)
                    for j, line in enumerate(split_row):
                        if re.findall(r'(\-I)', line):
                            line = line.replace('-I','')
                            if library_name == 'pandas-dev':
                                line = os.path.join('-I'+this_project,'ml_repos_cloned', library_name, 'pandas', line)
                            else:
                                line = os.path.join('-I'+this_project,'ml_repos_cloned', library_name, library_name, line)
                            split_row[j] = line
                    
                    _command = ' '.join(split_row)
                            
                    # command = 'clang++-10 --analyze -Xanalyzer '+_command+' '+_path
                    command = 'clang-tidy '+_path+' -checks=-*,clang-analyzer-* -- '+_command
                    #os.chdir(_path)

                    start_time = time.time()
                    output = subprocess.getoutput(command)
                    execution_time = time.time() - start_time
                    
                    subprocess.call('rm -rf *.plist', shell=True)
                    return output, execution_time


                if full_check and detector_name == 'infer':
                    command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe --starvation --racerd --pulse --loop-hoisting --biabduction -- gcc '+opt['command']+' '+filename
                    command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+opt['command']+' '+filename      
                else:
                    command_capture = 'infer --keep-going -- gcc '+opt['command']+' '+filename
                    command_analyze = 'infer analyze -- gcc '+opt['command']+' '+filename      

                start_time = time.time()
                subprocess.call(command_capture, shell=True)
                output = subprocess.getoutput(command_analyze)
                execution_time = time.time() - start_time

                subprocess.call('rm -rf infer-out', shell=True)
                subprocess.call('rm -rf *.o', shell=True)

            except Exception as e:
                print(e)
        else:
            try:
                new_list = []
                split_row = remove_white_spaces(split_row)
                split_row.remove(split_row[0])
                split_row.remove(split_row[-1])
                split_row.remove(split_row[-1])
                split_row.remove(split_row[-1])
                split_row.remove(split_row[-1])
                split_row.append('-c')

                command_ = ' '.join(split_row)

                if full_check and detector_name == 'clang':
                    split_row = remove_white_spaces(split_row)
                    split_row.remove(split_row[0])
                    split_row.remove(split_row[-1])
                    split_row.remove(split_row[-1])
                    split_row.remove(split_row[-1])
                    split_row.remove(split_row[-1])

                    command_ = ' '.join(split_row)

                    # command = 'clang++-10 --analyze -Xanalyzer '+command_+' '+opt['file']
                    command = 'clang-tidy '+opt['file']+' -checks=-*,clang-analyzer-* -- '+command_
                    # os.chdir('/'.join(opt['file'].split('/')[0:-1]))

                    start_time = time.time()
                    output = subprocess.getoutput(command)
                    execution_time = time.time() - start_time
                    
                    subprocess.call('rm -rf *.plist', shell=True)
                    return output, execution_time
                
                if full_check and detector_name == 'infer':
                    command_capture = 'infer --keep-going --no-print-logs --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe --starvation --racerd --pulse --loop-hoisting --biabduction -- gcc '+command_+' '+filename
                    command_analyze = 'infer analyze --bufferoverrun --uninit --resource-leak-lab --printf-args --nullsafe -- gcc '+command_+' '+filename
                else:
                    command_capture = 'infer --keep-going -- gcc '+command_+' '+filename
                    command_analyze = 'infer analyze -- gcc '+command_+' '+filename


                start_time = time.time()
                subprocess.call(command_capture, shell=True)
                output = subprocess.getoutput(command_analyze)
                execution_time = time.time() - start_time

                subprocess.call('rm -rf infer-out', shell=True)
                subprocess.call('rm -rf *.o', shell=True)

            except Exception as e:
                print(e)

    return output, execution_time

def _match(cl, loc):
    super_list = []
    flag_full = False
    flag_partial = False
    for sk, sub_cl in cl.items():
        super_list.append(tuple(sub_cl))
    if any(lower <= loc <= upper for (lower, upper) in super_list):
        flag_full = True
    if any(lower > loc or loc > upper for (lower, upper) in super_list):
        flag_partial = True
    return flag_full, flag_partial

def diff_based_matching(changed_lines, current_commit, detector_name, library_name, opt, full_check):

    save_source_code(current_commit.source_code_before, current_commit.filename)

    loc = len(current_commit.source_code_before.split('\n'))

    if os.path.isfile(os.path.join(this_project,current_commit.filename)):
        [output, execution_time] = run(library_name, opt, current_commit.filename, full_check, detector_name)
        
        if detector_name == 'infer':
            res = parse_infer(output)
        else:
            res = parse_clang(output)

        # detection_status = {'detected': []}
        detection_status = {'full_match': [], 'partial_match': []}
        if not isinstance(res[0], str):
            for loc, warning in res[0].items():
                # detection_status['detected'].append(warning)
                for k, cl in changed_lines.items():
                    [flag_full, flag_partial] = _match(cl, loc)
                    if flag_full:
                        detection_status['full_match'].append(warning)
                    if flag_partial:
                        detection_status['partial_match'].append(warning)
                    
    subprocess.call('rm -rf '+this_project+'/'+current_commit.filename, shell=True)

    return detection_status, current_commit, res, execution_time

def save_source_code(source_code, filename):
    split_source_code = source_code.split('\n')
    with codecs.open(filename, 'w') as f_method:
        for line in split_source_code:
            f_method.write("%s\n" % line)
        f_method.close()

def fixed_warning_base_matching(fix_commit, vul_commit, detector_name, library_name, opt, full_check):
    #save_source_code(vul_file_object.source_code_before, 'fix', vul_file_object.filename)
    save_source_code(vul_commit.source_code_before, vul_commit.filename)
    
    out = []
    flag = False
        
    if os.path.isfile(os.path.join(this_project, vul_commit.filename)):
        
        [output1, execution_time1] = run(library_name, opt, vul_commit.filename, full_check, detector_name)
        
        if detector_name == 'infer':
            res1 = parse_infer(output1)
        else:
            res1 = parse_clang(output1)

    subprocess.call('rm -rf '+os.path.join(this_project, vul_commit.filename), shell=True)
    
    save_source_code(vul_commit.source_code, vul_commit.filename)

    if os.path.isfile(os.path.join(this_project, vul_commit.filename)):
        [output2, execution_time2] = run(library_name, opt, vul_commit.filename, full_check, detector_name)
        
        if detector_name == 'infer':
            res2 = parse_infer(output2)
        else:
            res2 = parse_clang(output2)

    if not isinstance(res1, str):  
        set_1 = set(res1[1])
        set_2 = set(res2[1])

        wfixed = set_1 - set_2
        out.append(wfixed)
        if bool(wfixed):
            # x = find_wfix(wfixed, res1, detector_name)
            #out.append(x)
            flag = True
    else:
        flag = False
    
    subprocess.call('rm -rf '+os.path.join(this_project, vul_commit.filename), shell=True)
    

    return flag, vul_commit, res1, res2, execution_time1+execution_time2, out

def find_wfix(wfixed, res1):
    output = {}
    wfix = list(wfixed)
    flat_list = sorted({x for v in res1[0].values() for x in v})
    for item1 in wfix:
        for item2 in flat_list:
            if re.findall(r'(\:'+item1+r')', item2):
                output[int(REG_LOC_INFER.search(item2).group(1))] = item2
    return output

def combine_fixed_results(detection_status):
    data_list = []
    data_list.append('detected')
    j = 0
    for k, v in detection_status.items():
        j += 1
        if bool(v):
            data_list.append(v)
    return data_list, j

def combine_diff_results(detection_status):
    data_list = []
    j = 0
    for k, v in detection_status.items():
        if bool(v):
            data_list.append(k)
            for item in v:
                j += 1
                data_list.append(item)
    return data_list, j

def changed_lines_to_list(cl):
    global_list = []
    for k, v in cl.items():
        for sk, sv in v.items():
            global_list = global_list + sv
    return global_list

def convert_df_dict():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vul_data.csv'
    data = pd.read_csv(vic_path, sep=',')
    x = {}
    for index, rows in data.iterrows():
        x[rows[2].split('/')[-1]] = rows[1]
    return x


def main():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs'
    
    _id = 0

    for i, dir in enumerate(os.listdir(vic_path)):
                
        if user_names[i] == 'tensorflow' or user_names[i] == 'pytorch':
            repository_path = this_project+'/ml_repos_cloned/'+user_names[i]
        else:
            repository_path = this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0]

        v = "https://github.com/{0}/{1}{2}".format(user_names[i], dir.split('_')[1].split('.')[0],'.git')

        commit_base_link = "https://github.com/{0}/{1}/{2}/".format(user_names[i], dir.split('_')[1].split('.')[0], 'commit')

        if not os.path.exists(repository_path):
            subprocess.call('git clone '+v+' '+repository_path, shell=True)
                        
        vic_lib_path = os.path.join(vic_path, dir)

                        # load vulnerable inducing commits
        with open(vic_lib_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read(),strict=False)


        # file_counter = 0
        # valid_file_counter = 0
        # commit_counter = 0
        # for item in data:
        #     x = list(item.keys())
        #     r = Repo(repository_path)
        #     b = r.commit(x[0])
        #     _files = b.stats.files
        #     for k, v in _files.items():
        #         file_counter += 1
        #         if 'test' not in k  and k.split('.')[-1] in _extensions:
        #             valid_file_counter += 1
        # print('Total number of files and valid files for {} are: {}:{}'.format(dir.split('_')[1].split('.')[0], file_counter, valid_file_counter))
    

        file_counter = 0
        valid_file_counter = 0
        commit_counter = 0
        for item in data:
            x = list(item.keys())
                # r = Repo(repository_path)
                # b = r.commit(x[0])
                #_files = b.stats.files
            current_commit = PyDrillerGitRepo(repository_path).get_commit(x[0])
                #for k, v in _files.items():
            if bool(current_commit.modifications):
                commit_counter += 1
                for mod in current_commit.modifications:
                    file_counter += 1 
                    if 'test' not in str(mod.old_path) and 'test' not in str(mod.new_path) and 'test' not in mod.filename and mod.filename.split('.')[-1] in _extensions:
                        valid_file_counter += 1
        print('Total number of Commits and files and valid files for {} are: {}:{}:{}'.format(dir.split('_')[1].split('.')[0], commit_counter, file_counter, valid_file_counter))
            

                               

if __name__ == '__main__':
    main()