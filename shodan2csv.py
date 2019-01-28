import shodan,  csv,  argparse
import sys

''' Global vars is a section you may need to alter '''
DEFAULT_KEY = 'ENTER_YOUR_KEY_HERE!!!!!!!!'

#tags found through shodan
SHODAN_TAGS = ['IP','Instance ID','Object Name','Location','Application Software','Model Name','Description', 
                               'app.name',  'app.version',  'station.name',  'brandId',  'hostId',  'vmUuid']
#SHODAN_TAGS = [x.upper() for x in SHODAN_TAGS]   #CAPS - compatibility in string comparison >> DEPRECATED: DONE BELOW

#tags found through whois
WHOIS_TAGS    = ['Address','Country','city','OrgName','OrgID',
                      'StateProv','OrgTechPhone','OrgTechEmail','OrgNOCPhone','OrgNOCEmail',
                      'OrgAbusePhone','OrgAbuseEmail','RtechPhone','RtechEmail','info']
#WHOIS_TAGS = [x.upper() for x in WHOIS_TAGS]        #CAPS - compatibility in string comparison >> DEPRECATED: DONE BELOW


'''' End of Global vars section '''


def shodan_values(result,  hostinfo=None):
    result_in_list = result['data'].split('\n')
    
    '''We manipulate the output in order to find the tags that we are interested in which are
       defined at the beggining of the file.
       We want each tag_value to go to the correct column under the corresponding tag.
       Thus for each tag we search all the key:value pairs found through the search and
       if the key which is pair.split(':')[0] matches the tag, we add the corresponding value
       which is pair.split(':')[1] in the correct position in shodan_tags_value list. Thus 
       whois_tags_values[0] will have value for the first tag of whois_tags etc... '''
    shodan_tags_values = []
    for tag in SHODAN_TAGS:      #skip the IP we know that
        found = False
        
        #Append each tag found in search query
        for pair in result_in_list:
            #print 'pair : ',  pair
            if (pair.split(':')[0]).lower() == tag.lower():
                shodan_tags_values.append(pair.split(':')[1])
                found = True
                break         #tag found so break out of this for-pair
        
        if found == True:
            continue        #tag found so continue to next for-tag  (don't bother searching hostinfo)

        #Deepen more using the hostinfo from the host query to find more tags
        if hostinfo != None:
            s = str(hostinfo['data'][0])          #make the dict -> string
            if tag in s:
                #Dont try to understand this. Shodan api reply format is terrible!! messy dictionaries
                try:
                    pair = s[s.find(tag) : ].split('\\')[0]
                    tag_value = pair.split('=')[1]
                except IndexError:
                    try:
                        pair = s[s.find(tag) : ].split('\\')[0]
                        tag_value = pair.split('=')[1]
                    except IndexError:
                        tag_value = 'Unknown format'
                        print 'value for tag:',  tag,  ' in uknown format'
                        
                #append the value to the list and skip to the next for-tag
                shodan_tags_values.append(tag_value)
                found = True
                break
        
        #if flag is still false it means tag was not found neither in search nor in host query
        if found == False:
            shodan_tags_values.append('None')

    shodan_tags_values[0] = result['ip_str']            #dont forget to write down the IP :)
    
    return shodan_tags_values
    
    
def whois_values(ip,  verbosity='False'):
    import subprocess     #needed to call the external whois.py script

    if verbosity==True:
        print 'Performing whois search ...'

    #whois the IP
    options = {}
    whois_res = NICClient().whois_lookup(options, ip, 1)

    #convert the results from multiline string to list:
    result_in_list = whois_res.split('\n')
    
    '''We manipulate the output in order to find the tags that we are interested in which are
       defined at the beggining of the file.
       We want each tag_value to go to the correct column under the corresponding tag.
       Thus for each tag we search all the key:value pairs found through the search and
       if the key which is pair.split(':')[0] matches the tag, we add the corresponding value
       which is pair.split(':')[1] in the correct position in whois_tags_value list. Thus 
       whois_tags_values[0] will have value for the first tag of whois_tags etc... '''
    whois_tags_values = []
    for tag in WHOIS_TAGS:
        found = False
        for pair in result_in_list:
            #print 'pair : ',  pair
            if (pair.split(':')[0]).lower() == tag.lower():
                whois_tags_values.append(pair.split(':')[1])
                found = True
                #print 'found: ',  pair.split(':')[0]
                break
        if found == False:
            whois_tags_values.append('None')

    return whois_tags_values
    

def main():
    '''handle the command line args'''
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", type=str, help="your API key",  default=DEFAULT_KEY)
    parser.add_argument("-q", "--query", type=str, help="your query",  required=True)
    parser.add_argument("-v", "--verbosity", help="currently not working", default=False)
    args = parser.parse_args()
    
    #remove whitespaces from left and right
    query = args.query.lstrip().rstrip()
    key = args.key.lstrip().rstrip()
    
    # Wrap the request in a try/ except block to catch errors
    try:
        api = shodan.Shodan(args.key)
        # Search Shodan
        print 'Performing shodan search: "',  query,  '" ...'
        results = api.search(query)
        #results = api.search('BACNET')
        print 'Results found: %s' % results['total']
        print 'Results maching %s' % len(results['matches'])

        '''For each result (node) do some further lookups and store a list to row,
          which is list of lists. One row for each result'''
        rows = []      
        for result in results['matches']:
            if args.verbosity:
                print '\nIP: %s' % result['ip_str'] 
            
            if query.upper() != 'BACNET':
                #For each result(node) perform a host lookup to find more details
                if args.verbosity == True:
                    print 'Performing a {host} query to shodan...'
                hostinfo = api.host(result['ip_str'])
            else:
                hostinfo = None         #not needed for bacnet
                
            #Process the shodan results to find selected tags
            shodan_tags_values = shodan_values(result,  hostinfo)
            #For each result(node) perform a whois lookup to find more details
            whois_tags_values = whois_values(result['ip_str'],  args.verbosity)
            #we want each line in the csv to contain the corresponding value for each tag
            row = shodan_tags_values + whois_tags_values
            #Then append the row to the csv list. Rows is our csv output
            rows.append(row)

        # Finally write the results to a csv file with filename identical to the query that was performed
        with open(args.query+'.csv',   'w') as csvout:
            csvwriter = csv.writer(csvout, delimiter=',')
            csvwriter.writerow(SHODAN_TAGS+WHOIS_TAGS)
            for row in rows:
                csvwriter.writerow(row)
            
    except shodan.APIError, e:
            print 'Error: %s' % e

if __name__ == '__main__':
    main()
