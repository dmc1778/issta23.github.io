
import pandas as pd
import re, csv


data_addr = '/media/nimashiri/DATA/vsprojects/ICSE23/detection_results/static/results.csv'


data = pd.read_csv(data_addr, sep=',', encoding='utf-8')

c = 0
for idx, row in data.iterrows():
    c = c+1
    print(f"{c}/{len(data)}")
    if row['Marking'] == 'full_match':
        if re.findall(r'('+row['Filename']+')', row['Warning1']) or re.findall(r'(Found compiler error\(s\))', row['Warning1']):
            with open('./detection_results/static/results_new.csv', 'a', newline='\n') as fd:
                writer_object = csv.writer(fd)
                writer_object.writerow(list(row))