#!/usr/bin/python3

import sys, json

# This script was designed to update the keyword files with the user-specified ke yword changes
# This script is used to perform the update instead of generate_keywords.py, mostly for the sake of speed
# Since we want to display the updated results to the user, we needed a faster way of adding the keyword updates
# This script is used to implement the user-specified changes in the final keywords files, and nothing else

# This is the relative path from the script to the files it needs
relative_path = sys.path[0] + '/ttpkeywords/'

# These are the files for the user-specified additional keywords
f_user_enterprise_additions = relative_path + 'user_enterprise_keywords.json'
f_user_mobile_additions = relative_path + 'user_mobile_keywords.json'

# These are the files containing the keyword changes, with the user-specified keywords being values for the 'match_ignore' key
f_enterprise_exclusions = relative_path + 'excluded_enterprise_keywords.json'
f_mobile_exclusions = relative_path + 'excluded_mobile_keywords.json'

# The files that are being used to store the final set of keywords
f_final_enterprise_keywords = relative_path + 'final_enterprise_keywords.json'
f_final_mobile_keywords = relative_path + 'final_mobile_keywords.json'

# Setting up the variables based on the input
if sys.argv[1] == 'enterprise':
    user_additions = f_user_enterprise_additions
    user_exclusions = f_enterprise_exclusions
    keywords_file = f_final_enterprise_keywords
if sys.argv[1] == 'mobile':
    user_additions = f_user_mobile_additions
    user_exclusions = f_mobile_exclusions
    keywords_file = f_final_mobile_keywords

# Setting up the necessary variables by reading in the files
with open(user_additions, 'r') as file:
    addition_dict = json.load(file)
with open(user_exclusions, 'r') as file:
    exclusion_list = json.load(file)['match_ignore']

# Doing the update
with open(keywords_file, 'r+') as file:
    keyword_dict = json.load(file)
    file.seek(0)
    file.truncate()
    # Doing the additions first
    for key in addition_dict:
        if key in keyword_dict:
            keyword_dict[key].extend(addition_dict[key])
            # Removing any duplicates
            keyword_dict[key] = list(set(keyword_dict[key]))
    # Removing any of the user=specified keywords
    for key in keyword_dict:
        for elem in keyword_dict[key]:
            if elem in exclusion_list:
                keyword_dict[key].remove(elem)
    # Dumping everything back into the file
    json.dump(keyword_dict, file, indent = 4)



