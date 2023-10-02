#!/usr/bin/python3

import spacy, json, re, sys
from lemminflect import getAllInflections, getLemma
from rake_nltk import Metric, Rake
from pyattck import Attck

# This script was designed to generate a set ot [TTP] : [keyword] associations, and store them in a file
# Another script would then use that file to recommend a set of TTPs based on keywords found in the HTML of a provided URL
# This script makes use of multiple tools:
#   - The pyattck framework (https://github.com/swimlane/pyattck)
#       - Provides a list of Enterprise and Mobile techniques, including their name, their ttp id, and their description
#       - Provides a list of the tactics a technique is a member of; this us used to weed out any techniques that are not applicable to malware behavior (usually pre-attack tactics)
#       - Provides a list of tools that are often used in attacks, as well as the TTPs they are associated to
#   - The rake_ntlk keyword generator (https://pypi.org/project/rake-nltk/)
#       - Generates a list of keywords base don their frequency and prevalence in the provided text
#       - I'm using the technique descriptions from pyattck as the input for rake_ntlk
#   - The LemmInflect python module (https://github.com/bjascob/LemmInflect)
#       - LemmInflect is being used to generate inflections for the keywords, improving their coverage
#       - As an example: if the keyword 'scan the network', other variations such as 'scanned the network' and 'scans the network' are generated and added as keywords
# Once the keywords are generated, they're cleaned up to remove and generalized keywords
# The keywords are then stored in a json file, under the format {"ttp_id_here" : ["list", "of", "keywords", "here"]}
# That file is then accessed by the script that recommends the ttps when given a url to an article

##############################
#    VARIABLE DEFINITIONS    #
##############################

# Setting up the pyattck Attck object, to cycle through the latest Enterprise and Mobile TTPs
attack = Attck()

# The dictionary used to store and dump the keywords into the final_mobile_keywords or final_enterprise_keywords files
keyword_dict = {}

# List to store the final keywords
temp_keyword_list = []

# List of tactics to be ignored (those that are usually unapplicable, pre-attack tactics)
# To anyone changing this in the future, this is case sensitive, so make sure to write them as-is
excluded_tactics = ['Reconnaissance', "Resource Development"]

# Setting up some spaCy stuff to generate inflections later on
nlp = spacy.load('en_core_web_sm')

# This is the file path to the other necessary files
relative_path = sys.path[0] + '/ttpkeywords/'

# These are files containing terms to remove or ignore from the keywords, to improve their quality
f_undesired_enterprise_kwds = relative_path + 'excluded_enterprise_keywords.json'
f_undesired_mobile_kwds = relative_path + 'excluded_mobile_keywords.json'

# These are the files used to store the TTP ID : ['name', 'description'] associations
f_enterprise_ttp_descr = relative_path + 'enterprise_ttp_descriptions.json'
f_mobile_ttp_descr = relative_path + 'mobile_ttp_descriptions.json'
f_ttp_descr = relative_path + 'ttpDescr.json'

# These are the files used to provide additional keywords
f_enterprise_addtn = relative_path + 'additional_enterprise_keywords.json'
f_mobile_addtn = relative_path + 'additional_mobile_keywords.json'
f_add_kwds = relative_path + 'addKwds.json'

# These are the files used to store the generated keywords
f_enterprise_kwds = relative_path + 'final_enterprise_keywords.json'
f_mobile_kwds = relative_path + 'final_mobile_keywords.json'
f_final_kwds = relative_path + 'finKwds.json'

# These are the file containing the user-specified keywords
f_user_enterprise_kwds = relative_path + 'user_enterprise_keywords.json'
f_user_mobile_kwds = relative_path + 'user_mobile_keywords.json'

# A few names for tools that aren't added to the TTP associations
# Some tool names, such as 'Net', detect on a large amount of non-applicable text
rejected_tools = ['Net', 'Reg', 'Ping', 'cmd', 'Tor', 'ssh', 'Expand', 'QuasarRAT']

##############################
#    FUNCTION DEFINITIONS    #
##############################

def check_tactic(technique):
    '''Check whether a MITRE technique is a member of an excluded MITRE tactic.

    Input:
     - technique
       - pyattck technique object for the current technique being checked
    Output:
     - True if the technique is among the undesirable tactics
     - False if the technique is to be kept
    '''

    for tactic in technique.tactics:
        for excluded_tactic in excluded_tactics:
            if excluded_tactic in tactic.name:
                print(technique.id + ' Excluded - ' + tactic.name)
                return True

def extract_keywords(text):
    '''Use rake_nltk to generate a list of keywords for a given MITRE technique.
    
    Input:
     - text
       - A string containing the description for a MITRE technique
       - This is obtained using the technique.description member
    Output:
     - A list containing the automatically generated keywords
    '''
    
    # As a note: WORD_DEGREE is used here because generating kewyords based on their frequency usually leads to non-applicable keywords
    # The minimum length is also set to 2 words to filter out random words like "network" or "usual", that aren't unique enough
    rake = Rake(ranking_metric = Metric.WORD_DEGREE, min_length = 2, max_length = 4)
    rake.extract_keywords_from_text(text)
    return(rake.get_ranked_phrases())

def clean_up_keywords(raw_list, clean_list, excluded_keywords):
    '''Remove low-quality keywords from the list of generated keywords.

    Input:
     - raw_list
       - List containing the unrefined keywords
     - clean_list
       - List used to store the refined keywords
     - excluded_keywords
       - Dictionary containing the keyword exclusions
    Output:
     - No specific return value
     - The cleaned up keywords are copied over into the provided clean_list list
    '''

    for term in raw_list:

        # Flag used to decide whether the term is kept or not
        keep_flag = True

        # If one of the terms flagged for removal is found in the generated keyword, it is removed from the keyword
	# The 'replace' key is for terms that are removed from the generated keywords, with the remainder acting as the refined keywords
        for removed_term in excluded_keywords['replace']:
            if (removed_term in term) and (len(term.split()) > 3):
                term = term.replace(removed_term, '')
                break
        # Checks to see if one of the ignored terms are found. If so, start the next loop iteration without keeping the term
	# The 'ignore' key is to remove any generated keywords if any of the 'ignored' terms are found in them
        for ignored_term in excluded_keywords['ignore']:
            if (ignored_term in term):
                keep_flag = False
                break
        if keep_flag:
            # The 'ignore_if_len_lt_3' does the same thing as 'ignore' but only if a set of generated keywords is 2 words or less
            for ignored_term_lt_3 in excluded_keywords['ignore_if_len_lt_3']:
                if (ignored_term_lt_3 in term) and (len(term.split()) < 3):
                    keep_flag = False
                    break
        if keep_flag:
            # Replacing any leftover double spaces along the way
            clean_list.append(term.replace('  ', ' '))

    raw_list.clear()

def add_supplementary_keywords(keywords, name, current_keywords):
    '''Add supplementary, manually created keywords to the list of generated keywords.

    Input:
     - keywords
       - Dictionary containing the keywords to add
       - Read from one of the additional keywords files
       - Formatted as {"String to look for in technique name" : ["list", "of", "keywords"]}
     - name
       - String containing the name for the current technique
       - The name is obtained from pyattck, using the technique.name member
     - current_keywords
       - List containing the current set of keywords
       - The additional keywords are added to this list
    Output:
     - No specific return value
     - The supplementary keywords are added to the current_keywords list
    '''

    for keyword in keywords:
        if keyword in name.lower():
            # This is to deal with a few exceptions such as "Non-Application Layer Protocol" and "Application Layer Protocol"
            # Where it's difficult to distinguish between the two when generating the supplementary keywords
            # Using the above example, this prevents the "Application Layer Protocol" keywords from being added to the "Non-Application Layer Protocol" ones
            if ('non-' not in name.lower() and 'non-' not in keyword.lower()):
                current_keywords.extend(keywords[keyword])

def generate_inflections(keywords_list, current_keywords):
    '''Uses LemmInflect and spaCy to generate inflections for existing keywords, increasing coverage.

    Input:
     - keywords_list
       - A copy of the list containing the current keywords
       - A copy is used here to avoid infinite loops
     - current_keywords
       - List containing the current set of keywords
       - The generated inflections are copied into this list
    Output:
     - No specific return value
     - The generated inflections are added to the current_keywords list
    '''

    # Looping through every keyword (should technically be called key term instead) in the list of keywords
    for element in keywords_list:
        element_words = element.split()
        # Looping through every word in the keywords (or key terms) to check for any words that are verbs
        for element_word in element_words:
            doc = nlp(element_word)
            # If the current word was found to be a verb, then find all of its inflections so that they can be added as keywords
            if doc[0].pos_ == 'VERB':
                # The word lemma is needed before any inflections can be found
                word_lemma = getLemma(element_word, upos='VERB', lemmatize_oov = True)[0]
                inflections = getAllInflections(word_lemma, upos='VERB')
                # This loop then adds a keyword to the list, containing every generated inflection (i.e. 'attacks the victim', 'attacked the victim', etc. are all added as keywords)
                for inflection in inflections:
                    if inflections[inflection][0] not in element:
                        current_keywords.append(element.replace(element_word, inflections[inflection][0]))
    keywords_list.clear()

def add_associated_commands(attack_technique, current_keywords):
    '''Add any commands associated to a technique as keywords for said technique.

    Input: 
     - attack_technique
       - The pyattck technique object for the current technique
     - current_keywords
       - List containing the current set of keywords
       - The associated commands are copied into this list
    Output:
     - No specific return value
     - The associated commands are added to the current_keywords list
    '''

    # Doing this if statement because some attack_technique.command_list are of NoneType (because they're empty)
    if  attack_technique.command_list is not None:
        for command in attack_technique.command_list:
            # This removes some of the shorter commands that would trip on most articles, and aren't unique enough (i.e. 'id', 'Net', 'Reg')
            if len(command) > 6:
                current_keywords.append(command)

def remove_user_specifed_keyword_exclusions(excluded_keywords):
    '''Removes all of the keywords users have submitted for removal.

    Input:
     - excluded_keywords
       - The dictionary containing the excluded keywords for the specified matrix
    Output:
     - No specific return value
     - This function removes the excluded keywords from the keyword_dict's lists
    '''

    for key in keyword_dict:
        for elem in keyword_dict[key]:
            for ignore_word in excluded_keywords["match_ignore"]:
                if elem == ignore_word:
                    keyword_dict[key].remove(elem)
            

def add_associated_tools(tool_list):
    '''Add tool names as keywords for all techniques said tools are associated to.

    Input:
     - tool_list
       - A list of pyattck tool objects
       - This is obtained from wither attack.enterprise.tools or attack.mobile.tools
    Output:
     - No specific return value
     - The associated tool names are added to the keyword_dict dictionary
    '''

    for tool in tool_list:
        # If the tool name is among the rejected tool names, ignore it and start the next loop iteration
        if tool.name in rejected_tools:
            continue
        for technique in tool.techniques:
            curr_id = technique.id.split('.')[0]
            if ('deprecated' not in technique.description) and (tool.name not in keyword_dict[curr_id]):
                keyword_dict[curr_id].append(tool.name)
                # Also adding any alternate tool names to the list
                if tool.additional_names is not None:
                    for name in tool.additional_names:
                        # If the tool name is among the rejected tool names, ignore it and start the next loop iteration
                        if tool.name in rejected_tools:
                            continue
                        keyword_dict[technique.id.split('.')[0]].append(name)

def add_user_keywords(user_file):
    '''Add user-specified keywords to the final set of keywords being stored in the output file.

    Input:
     - user_file
       - The filename of the file being used to store the user-specified keywords

    Output:
     - This function has no specific return value. Instead, the user-specified keywords are added to the keyword_dict dictionary
     - The keywirds are only added of their key is already in the dictionary. This prevents adding TTP IDs containing typos
    '''
    with open(user_file) as file:
        user_dict = json.load(file)
        for key in user_dict:
            if key in keyword_dict:
                keyword_dict[key].extend(user_dict[key])


def generate_keywords(keyword_list, techniques, additional_keywords_file, excluded_words_file, final_keywords_file, ttp_description_file, tool_list, user_file):
    '''Generate a whole set of keywords for a single matrix.

    Input:
     - keyword_list
       - The list used to temporarily store the generated keywords before adding them to the final dictionary
     - techniques
       - The list of technique objects, either sent from the mobile or the enterprise pyattck objects
     - additional_keywords_file
       - The name of the file containing additional keywords to add to the generated keywords
     - excluded_words_file
       - The name of the file containing a set of terms used to clean up the generated keywords, improving their quality
     - final_keywords_file
       - The name of the file used to store the final set of generated keywords
     - ttp_description_file
       - The name of the file used to store the TTP IDs, names, and descriptions that are obtained from pyattck
     - tool_list
       - The list of tools associated to a given class of TTPs (i.e. enterprise tools vs mobile tools)
     - user_file
       - Filename for the file containing the user-specified keywords
    Output:
     - No specific return value
     - A full set of keywords is generated for the desired matrix, and stored in the designated output file
    '''

    # Grabbing some supplementary keywords to add to the TTPs, with the keywords being associated to the ttp name
    file = open(additional_keywords_file, 'r')
    supplementary_keywords = json.load(file)
    file.close()

    # Grabbing the dictionary containing the keywords to remove hen refining keywords
    file = open(excluded_words_file)
    excluded_dict = json.load(file)
    file.close()

    for technique in techniques:

        # This is a check to see whether a technique is a part of the undesired tactics. Pre-attack tactics can't be applied to a malware's behavior
        # If the technique is among the non-applicable tactics, then ignore it, and start the next loop iteration
        if check_tactic(technique):
            continue

        # Some of the pyattck techniques return 404/don't exist, so they get skipped if the description is empty
        if technique.description is None:
            continue

        # Some techniques are deprecated, so there's no use in adding them in. If the technique is deprecated, start the next loop iteration
        if 'deprecated' in technique.description:
            print(technique.id + ' Deprecated')
            continue
        else:
            print(technique.id)

        # Using rake_nltk to generate the keywords using the technique's description
        raw_keyword_list = extract_keywords(technique.description)

        # Cleaning up the keywords, and adding them to keyword_list
        clean_up_keywords(raw_keyword_list, keyword_list, excluded_dict)
        raw_keyword_list.clear()

        # Adding any applicable supplementary keywords
        add_supplementary_keywords(supplementary_keywords, technique.name, keyword_list)

        # Generating the inflections for the keywords, to increase coverage
        generate_inflections(keyword_list.copy(), keyword_list)

        # Adding the technique name to the list of keywords
        keyword_list.append(technique.name)

        # Making sure everything is lowercase. The script that does the recommendations converts everything to lowercase when searching for keywords
        keyword_list = [term.lower() for term in keyword_list]

        # Using pyattck to add commands associated to a given tpp to that ttp's set of keywords
        add_associated_commands(technique, keyword_list)

        # Putting the keywords in the dict, to append them to the json file
        for keyword in keyword_list:
            keyword_dict[technique.id] = []
            keyword_dict[technique.id].extend(keyword_list)
        keyword_list.clear()

        # Removing any duplicates
        keyword_dict[technique.id] = list(set(keyword_dict[technique.id]))

    # Using pyattck's list of tools to add tool names to any ttps they are associated with
    add_associated_tools(tool_list)

    # Adding the user-specified keywords
    add_user_keywords(user_file)

    # Doing some final cleanup before dumping the keywords
    remove_user_specifed_keyword_exclusions(excluded_dict)

    # Putting the generated keywords in the provided output file
    keywords_file = open(final_keywords_file, 'w')
    json.dump(keyword_dict, keywords_file, indent = 4)
    keywords_file.close()
    keyword_dict.clear()

def generate_ttp_descriptions(output_file, techniques):
    '''Generate a short description for each TTP that is currently in use (not deprecated).

    Input:
     - output_file
       - The file used to store the generated short descriptions
     - techniques
       - A list of technique objects, for either the enterprise or mobile techniques
    '''
    
    # This is the dictionary that will be dumped to the json file
    dump_dict = {}

    description_file = open(output_file, 'w')

    for technique in techniques:
        
        # Some of the pyattck techniques return 404/don't exist, so they get skipped if the description is empty
        if technique.description is None:
            continue

        # These lines grab the first sentence in the description, and remove any text between ()
        # Then it assigns the description as the value in dump_dict, with the ttp ID acting as the associated keyword
        description = re.split('\.\x20|\.\n', technique.description)[0] + '.'
        description = re.sub(r'\([^)]*\)', '', description)

        # Some of the ttp descriptions simply state that the TTP is depracated. If that's the case. then the TTP is ignored
        if 'deprecated' not in description:
            # Setting a blank list up so that I can just use append()
            dump_dict[technique.id] = []
            # Adding in the TTP's name
            dump_dict[technique.id].append(technique.name)
            # Removing a few characters to clean up the descriptions
            clean_desc = description.replace('\n', '')
            clean_desc = clean_desc.replace('\u2019', "'")
            dump_dict[technique.id].append(clean_desc)

    json.dump(dump_dict, description_file, indent = 4)
    description_file.close()
    dump_dict.clear()


########################################
#    THE CODE BEING RUN STARTS HERE    #
########################################

if len(sys.argv) == 1:

    # Doing the enterprise keyword and description generation
    generate_keywords(temp_keyword_list, attack.enterprise.techniques, f_enterprise_addtn, f_undesired_enterprise_kwds, f_enterprise_kwds, f_enterprise_ttp_descr, attack.enterprise.tools, f_user_enterprise_kwds)
    generate_ttp_descriptions(f_enterprise_ttp_descr, attack.enterprise.techniques)

    # Doing the mobile keyword and description generation
    generate_keywords(temp_keyword_list, attack.mobile.techniques, f_mobile_addtn, f_undesired_mobile_kwds, f_mobile_kwds, f_mobile_ttp_descr, attack.mobile.tools, f_user_mobile_kwds)
    generate_ttp_descriptions(f_mobile_ttp_descr, attack.mobile.techniques)

elif sys.argv[1].lower() == 'enterprise':
    print('Generating Enterprise Keywords')
    generate_keywords(temp_keyword_list, attack.enterprise.techniques, f_enterprise_addtn, f_undesired_enterprise_kwds, f_enterprise_kwds, f_enterprise_ttp_descr, attack.enterprise.tools, f_user_enterprise_kwds)
    generate_ttp_descriptions(f_enterprise_ttp_descr, attack.enterprise.techniques)

elif sys.argv[1].lower() == 'mobile':
    print('Generating Mobile Keywords')
    generate_keywords(temp_keyword_list, attack.mobile.techniques, f_mobile_addtn, f_undesired_mobile_kwds, f_mobile_kwds, f_mobile_ttp_descr, attack.mobile.tools, f_user_mobile_kwds)
    generate_ttp_descriptions(f_mobile_ttp_descr, attack.mobile.techniques)

print('Done!')


