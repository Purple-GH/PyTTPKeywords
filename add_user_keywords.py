#!/usr/bin/python3

import sys, json
from collections import defaultdict

# This script was designed to allow users to add TTP:keyword associations
# The input parameters for the script are as follows:
# - python add_user_keywords.py [enterprise|mobile] "Txxxx:keywords,to add,here:Txxxx:other,keywords to add,etc."
# - The "Txxxx" in this case represents the TTP ID, i.e. T1234

# This is the relative path from the script to the files it needs
relative_path = sys.path[0] + '/ttpkeywords/'

# These are the output files for the user-specified keywords
# I decided against using additional_enterprise_keywords.json and additional_mobile_keywords.json as the output files
# The files mentionned above allow for multiple keywords to be added to ttps with similar name contents
# While this script allows adding keywords to a specified TTP ID
enterprise_file = relative_path + 'user_enterprise_keywords.json'
mobile_file = relative_path + 'user_mobile_keywords.json'

# Setting up the variables according to the provided parameters when running the script
if sys.argv[1] == 'enterprise':
    selected_file = enterprise_file
elif sys.argv[1] == 'mobile':
    selected_file = mobile_file
else:
    print('Invalid matrix selected!')
    print('Please run the script using the following parameters:')
    print('python add_user_keywords.py [mobile|enterprise] "T1234:keywords to add,separated,by,commas:T5678:same,thing,here,etc."')
    sys.exit()

print(sys.path[0])

# Adding the keywords
with open(selected_file, 'r+') as file:
    keyword_dict = json.load(file)
    file.seek(0)
    input_list = sys.argv[2].split(':')
    # Incrementing by 2 here because of how the input is formatted
    # Even index numbers represent TTP IDs, while odd index numbers represents the keywords
    for i in range(0, len(input_list), 2):
        keyword_dict.setdefault(input_list[i],[]).extend(input_list[i+1].split(','))
        keyword_dict[input_list[i]] = list(set(keyword_dict[input_list[i]]))
    json.dump(keyword_dict, file, indent = 4)
