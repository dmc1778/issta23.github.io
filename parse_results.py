import os, json
import pandas as pd
import re, csv
from pydriller import GitRepository as PyDrillerGitRepo

d = {'Library': 'Test', 'CWE': 'Test', 'Commit': 'Test'}

this_project = os.getcwd()
REG_VUL_TYPE_INFER = re.compile('error\:(.*)')
REG_LOC_INFER = re.compile('(\d+)\:\serror\:')

user_names = ['mlpack', 'numpy', 'pandas-dev', 'pytorch' ,'scipy', 'tensorflow']

def count_vic_vfc():
    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vul_data.csv'

    rdata = pd.read_csv(vic_path, sep=',')

    vic_path = '/media/nimashiri/DATA/vsprojects/ICSE23/data/vic_vfs'

    parse_able_commits = pd.DataFrame(columns=['Library', 'CWE', 'Commit'], index=None)

    for i, dir in enumerate(os.listdir(vic_path)):
        vic_lib_path = os.path.join(vic_path, dir)

        with open(vic_lib_path, 'r', encoding='utf-8') as f:
            data = json.loads(f.read(),strict=False)

        if user_names[i] == 'tensorflow' or user_names[i] == 'pytorch':
            repository_path = this_project+'/ml_repos_cloned/'+user_names[i]
        else:
            repository_path = this_project+'/ml_repos_cloned/'+user_names[i]+'/'+dir.split('_')[1].split('.')[0]

        i = 0
        j = 0
        files = []
        commits = []
        for counter, item in enumerate(data):
            i = i + 1
            x = list(item.keys())   
            if bool(item[x[0]]):
                j += 1
                for k, v in item.items():
                    for sub_item in v:
                        for c in sub_item['previous_commits']:
                            commits.append(c[0])   
                        files.append(sub_item['file_path'])

        

        # print('{} library has {} number of valid VFCs'.format(dir.split('_')[1].split('.')[0], j))
        # print('{} library has {} number of VICs'.format(dir.split('_')[1].split('.')[0], len(commits)))
        # print('{} library has {} number of unique VICs'.format(dir.split('_')[1].split('.')[0], len(set(commits))))
        # print('{} library has {} number of vulnerable files'.format(dir.split('_')[1].split('.')[0], len(files)))
        # print('{} library has {} number of unique vulnerable files'.format(dir.split('_')[1].split('.')[0], len(set(files))))
        # print('################################################################################')

        i = 0
        j = 0

        current_lib_data = rdata[((rdata.iloc[:, 0] == dir.split('_')[1].split('.')[0]))]

         # = pd.DataFrame([d], index=None)
        new_df = pd.DataFrame(columns=['Library', 'CWE', 'Commit'], index=None)

        for counter, item in enumerate(data):
            j = j + 1
            x = list(item.keys())
            current_commit = PyDrillerGitRepo(repository_path).get_commit(x[0])
            if len(current_commit.modifications) > 0:
                i = i + 1
                for idx in range(len(current_lib_data)):
                    if x[0] == current_lib_data.iloc[idx, 2].split('/')[-1]:
                        new_df = new_df.append(current_lib_data.iloc[idx, :])

        print('{} library has {} VFCs'.format(dir.split('_')[1].split('.')[0], j))
        print('{} library has {} parseable VFCs'.format(dir.split('_')[1].split('.')[0], i))
        print('##############'
                )

        parse_able_commits = parse_able_commits.append(new_df)
    parse_able_commits.to_csv('data/parseable_commits.csv', sep=',', index=None)
   
    # j = 0
    # i = 0
    # for index, row in enumerate(rdata):

    #     if rdata.iloc[index, 0] == 'tensorflow' or rdata.iloc[index, 0] == 'pytorch':
    #         repository_path = this_project+'/ml_repos_cloned/'+rdata.iloc[index, 0]
    #     else:
    #         repository_path = this_project+'/ml_repos_cloned/'+rdata.iloc[index, 0]+'/'+rdata.iloc[index, 0]

    #     j = j + 1
    #     try:
    #         current_commit = PyDrillerGitRepo(repository_path).get_commit(rdata.iloc[index, 2].split('/')[-1])
    #         if len(current_commit.modifications) > 0:
    #             i = i + 1
    #     except Exception as e:
    #         pass

    #     print('{} library has {} VFCs'.format(rdata.iloc[index, 0], j))
    #     print('{} library has {} parseable VFCs'.format(rdata.iloc[index, 0], i))
    #     print('##############')

def find_infer_cwe(warning):
    cwe_final_list = []
    warning = warning.split('\\\\n')
    for line in warning:
        if REG_LOC_INFER.search(line):
            cwe_final_list = cwe_final_list + [REG_VUL_TYPE_INFER.search(line).group(1)]
        break
    return cwe_final_list, cwe_final_list


def find_regex_groups(warning):
    war = []
    cwe_list = []
    # v = '\\n'.join(warning)
    if re.findall(r'CWE-(\d+)', warning):
        x = re.findall(r'CWE-(\d+)', warning)
        for cwe_ in x:
            cwe_list.append('CWE-'+cwe_)
        return cwe_list, re.findall(r'\)((.|\n)*?)\(', warning)[0][0]
    if re.findall(r'\(buffer\)\sstrlen\:', warning):
        cwe_list.append('CWE-126')
        return cwe_list, re.findall(r'\)((.|\n)*?)\\0-', warning)

def find_rat_types(warning):
    if re.findall(r'<type.*>((.|\n)*?)<\/type>', warning):
        x = list(re.findall(r'<type.*>((.|\n)*?)<\/type>', warning)[0])
        del x[-1]
    if re.findall(r'resulting in a\s(.*?)\.', warning):
        x = re.findall(r'resulting in a\s(.*?)\.', warning)
    return x, re.findall(r'<message.*>((.|\n)*?)<\/message>', warning)[0][0]

def find_cppcheck_cwe(warning):
    war = []
    cwe_list = []
    # v = '\\n'.join(warning)
    if re.findall(r'cwe=\"(\d+)\"', warning):
        x = re.findall(r'cwe=\"(\d+)\"', warning)
        y = re.findall(r'id="((.|\n)*?)"', warning)
        for cwe_ in x:
            cwe_list.append('CWE-'+cwe_)

        for id_ in y:
            war.append(id_[0])
    return cwe_list, war

def parse_(warning, tool_name):
    cwe_final_list = []

    if tool_name == 'flawfinder':
        [cwe_list, msg] = find_regex_groups(warning)

    if tool_name == 'rats':
        [cwe_list, msg] = find_rat_types(warning)

    if tool_name == 'cppcheck':
        [cwe_list, msg] = find_cppcheck_cwe(warning)

    if tool_name == 'infer':
        [cwe_list, msg] = find_infer_cwe(warning)

    for cwe in cwe_list:
        cwe_final_list = cwe_final_list + [cwe]
    return cwe_final_list, msg

def get_vul_freq():
    warning_list = []
    data = pd.read_excel('data/ICSE2023.xlsx')
    for index, row in data.iterrows():
        row = row.dropna()
        for item in row:
            if re.findall(r'\/media\/nimashiri\/DATA\/vsprojects\/', str(item)) or re.findall(r'<severity>', str(item)) or re.findall(r'<error id=', str(item)) or re.findall(r'error:\s', str(item)):
                [cwe_final_list, msg] = parse_(item, row['Tool'])
                for cwe in cwe_final_list:
                    vul_freq_data = [row['Tool'], row['Library']]
                    vul_freq_data = vul_freq_data + [cwe]
                    vul_freq_data = vul_freq_data + [msg]
                    vul_freq_data = [row['id']] + vul_freq_data

                    with open('vul_frequency2.csv', 'a', newline='\n') as fd:
                        writer_object = csv.writer(fd)
                        writer_object.writerow(vul_freq_data)

def parse_results():

    header_labels = ['id',	'tool',	'mapping','lib','time','commit', 'commit2','filename','filepath', 'added','deleted','numwarning','status']

    # data = pd.read_csv('detection_results/results.csv', delimiter=",", encoding='utf-8')
    # data = data[data.iloc[:, 11] > 0]
    # data.to_csv('detection_results/limited/limited_results.csv', sep=',', index=False)

    # data = pd.read_csv('detection_results/results_true.csv', delimiter=",", encoding='utf-8')
    # data = data[data.iloc[:, 11] > 0]
    # data.to_csv('detection_results/limited/limited_results_true.csv', sep=',', index=False)

    # data = pd.read_csv('detection_results/infer_fullcheck/results.csv', delimiter=",", encoding='utf-8')
    # data = data[data.iloc[:, 11] > 0]
    # data.to_csv('detection_results/infer_fullcheck/limited/limited_results.csv', sep=',', index=False)

    # data = pd.read_csv('detection_results/infer_fullcheck/results_true.csv', delimiter=",", encoding='utf-8')
    # data = data[data.iloc[:, 11] > 0]
    # data.to_csv('detection_results/infer_fullcheck/limited/limited_results_true.csv', sep=',', index=False)

    ############################################
    data = pd.read_csv('detection_results/results_fix.csv', delimiter=",", encoding='utf-8')
    data = data[data.iloc[:, 11] > 0]
    data.to_csv('detection_results/limited/limited_results_fixed.csv', sep=',', index=False)

    data = pd.read_csv('detection_results/infer_fullcheck/results_fixed.csv', delimiter=",", encoding='utf-8')
    data = data[data.iloc[:, 11] > 0]
    data.to_csv('detection_results/infer_fullcheck/limited/limited_results_fixed.csv', sep=',', index=False)


if __name__ == '__main__':
    # parse_results()
    # get_vul_freq()
    get_vul_freq()