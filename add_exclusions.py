#!/usr/bin/python3

import sys, json

relative_path= sys.path[0] + '/ttpkeywords/'

enterprise_file = relative_path + 'excluded_enterprise_keywords.json'
mobile_file = relative_path + 'excluded_mobile_keywords.json'

def append_removed_keywords(input_string, file_name):
    removal_list = input_string.split(',')
    with open(file_name, 'r+') as file:
        keyword_dict = json.load(file)
        keyword_dict['match_ignore'].extend(removal_list)
        keyword_dict['match_ignore'] = list(set(keyword_dict['match_ignore']))
        file.seek(0)
        file.truncate()
        json.dump(keyword_dict, file, indent = 4)

string_input = sys.argv[2]

if sys.argv[1].lower() == 'enterprise':
    append_removed_keywords(string_input, enterprise_file)
    sys.exit()
elif sys.argv[1].lower() == 'mobile':
    append_removed_keywords(string_input, mobile_file)
    sys.exit()
else:
    print('Script: add_exclusions.py')
    print('Usage: "python add_exclusions.py [mobile|enterprise] "comma,separated,string,of,values,to,remove"')
    sys.exit()
