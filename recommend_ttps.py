#!/usr/bin/python3

import json, requests, sys, os
from bs4 import BeautifulSoup

# This function is used to proide information abot the script to the user
def print_information():
		print('\nScript: [' + sys.argv[0] + ']')
		print('Parameters: ' + sys.argv[0] + ' [enterprise|mobile] [url]')
		print('  - [enterprise|mobile]: Specification for which matrix to use when recommending TTPs')
		print('  - [url]: The URL for the web page that is being checked for keywords')
		print('  - Run "' + sys.argv[0] + ' -help" to view this information again\n')

# If no URL was provided in the input, provide the user with information
if len(sys.argv) == 1:
	# Printing out information about the program to the user
	print_information()
	sys.exit()

# This is the path to the json files
dir_path = os.path.dirname(os.path.realpath(__file__))
path_to_files = os.path.join(dir_path, 'ttpkeywords/')

# If the user entered the "-help" command, print the script information to the screen.
if sys.argv[1].lower() == '-help':
	print_information()
	sys.exit()
# Choosing the keyword and description files to open based on the provided input
elif sys.argv[1].lower() == 'enterprise':
	keyword_file = path_to_files + 'final_enterprise_keywords.json'
	description_file = path_to_files + 'enterprise_ttp_descriptions.json'
elif sys.argv[1].lower() == 'mobile':
	keyword_file = path_to_files + 'final_mobile_keywords.json'
	description_file = path_to_files + 'mobile_ttp_descriptions.json'
else:
	print('The provided parameters were incorrect.')
	print('Please review the following information to run the script:')
	print_information()
	sys.exit()

# Setting up the url
reference_url = sys.argv[2]

# Getting the ttp keywords from the selected file
# The keywords age generated in the generate_keywords.py script
json_file = open(keyword_file)
word_ttp_assoc = json.load(json_file)
json_file.close()

# Getting the ttp descriptions
# The descriptions are generated in the generate_keywords.py script
json_file = open(description_file)
ttp_reason = json.load(json_file)
json_file.close()

# This is the string that stores the set of recommended TTPs
recommended_ttp = ''

# Grabbing the HTML from the website
html_text = requests.get(reference_url).text
soup = BeautifulSoup(html_text, 'html.parser')

# This is to check whether scripts are being blocked from scraping the website
soup_title = soup.find('title').get_text()
if 'used Cloudflare to restrict access' in soup_title:
	print('\n[Failed] - Cloudflare is preventing this script from accessing the website.')
	print('Access to [' + reference_url + "] is being blocked by Cloudflare's IUAM.")
	sys.exit()
if '403 forbidden' in soup_title.lower():
    print('The website returned "403 Forbidden" when the script tried to access it.')

# Only keeping the 'p' tags, to remove as much irrelevant text as possible
contents = []
for x in soup.find_all(['p', 'table']):
	contents.append(x.get_text())

contents = (' ').join(contents)
contents = contents.lower()

for key in word_ttp_assoc:
	for keyword in word_ttp_assoc[key]:
		if keyword.lower() in contents:
			# Adding a third list element to the found TTPs to store the found keywords
			if len(ttp_reason[key]) == 2:
				ttp_reason[key].append('')
			ttp_reason[key][2] = ttp_reason[key][2] + " ('" + keyword + "')"
			if key not in recommended_ttp:
				recommended_ttp = recommended_ttp + key + ' '

for ttp in ttp_reason:
	if ttp in recommended_ttp:
		print('[' + ttp + ']' +  ' - ' + ttp_reason[ttp][0] + ttp_reason[ttp][2])
		print(ttp_reason[ttp][1] + '\n')
if len(recommended_ttp.split()) == 0:
    print('No TTPs to recommend!')
print(recommended_ttp)

