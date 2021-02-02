import requests
import argparse
import json
from urllib.parse import quote

class Colors:
    INFO = '\033[95m'
    RESULTS = '\033[94m'
    OK = '\033[92m[!]'
    BANNER = '\033[96m[+]'
    WARN = '\033[93m[w]'
    FOUND = '\033[91m[!]'  
    TITLE = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    HREF = '\033[90m'

class CVSS:
    INFO = '\033[37m'
    LOW = '\033[94m'        # light blue
    MEDIUM = '\033[33m'     # yellow
    HIGH = '\033[91m'       # red
    CRITICAL = '\033[95m'   # purple
        
    def get_color(self, score=0):
        if score >= 0.1 and score < 3.9:
            return self.LOW
        elif score >= 4 and score < 7:
            return self.MEDIUM
        elif score >= 7 and score < 9:
            return self.HIGH
        elif score >= 9:
            return self.CRITICAL
        else:# score <= 0 or score == '':
            return self.INFO

def save(data, filename='sploitus.json'):
    ''' store data to file json '''
    with open('results.json','w+') as ofile:
        json.dump(data, ofile,indent=4)  

def post(data):
    ''' execute Sploitus (https://sploitus.com) POST request '''
    # Headers
    base_url = 'https://sploitus.com/search'
    headers = {
        'User-Agent':'Mozilla/5.0', 
        'Content-Type': 'application/json', 
        'Accept': 'application/json'
    }

    try:
        response = requests.post(base_url, headers=headers, json=data, timeout=5)         
    except requests.exceptions.Timeout as timeout:
        print(Colors.WARN,'Timed out. Retrying...', Colors.ENDC)        
        response = post(data)
    except requests.exceptions.RequestException as exc:  
        raise SystemExit(exc)    
    return response

def search(query, sort='default', p_type='exploits', offset=0, total=10, check_all_exploits=False, _max=10):        
    ''' build the search query and parse resluts '''
    # inti CVSS() to store data
    cvss = CVSS()
    finaljson = {'exploits':[]}

    # POST data parameters
    data = {
        'offset': offset,
        'query': query,
        'sort': sort,
        'title': 'false',
        'type': p_type,
    }
    
    # post requests
    r = post(data).json()
    # get the number of exploit found and print    
    total = r['exploits_total']    
    print(cvss.get_color(total) + '[+]', 'Available exploits {}\n'.format(str(total)), Colors.ENDC)
    
    if total > 0:
        #print Header        
        print('', Colors.BOLD, '{0:6}'.format('SCORE'),  '{:15}'.format('TYPE'), '{0:12}'.format('PUBLISHED'), '{}'.format('TITLE [LINK]'), Colors.ENDC)
    
    # retrieve data by 10 results per query. Only stop if MAX has been requested. 
    while offset < total:

        if offset == 10 and not check_all_exploits and not _max != 10:
            print('{}'.format('\n'), Colors.BANNER + ' Use `--view-all` to retrieve the entire exploits list\n', Colors.ENDC)            
            exit()
        if offset >= _max and _max != 10: 
            exit()
        else:
            # set new offset for result pagination
            data['offset'] = offset
        
        # firs query
        results = post(data).json()        
        for exploit in results['exploits']:     
            finaljson['exploits'].append(exploit)
            href = exploit['href'] if 'href' in exploit and exploit['href'] != '' else 'n/a'
            score = exploit['score'] if 'score' in exploit else '0'

            if 'type' in exploit and p_type == 'exploits':               
                print(cvss.get_color(int(score)), '{0:6}'.format(score), Colors.ENDC, 
                                '{: <15}'.format(exploit['type']), Colors.ENDC, end='')
            else:
                print(Colors.TITLE,'{0:5}'.format(' [!]'), Colors.ENDC, 
                                '{: <15}'.format(exploit['type']), Colors.ENDC, end='')

            if 'published' in exploit:
                print('{0:10}  '.format(exploit['published']), end='')

            print(cvss.get_color(int(score)), '{}'.format(exploit['title']),Colors.HREF,
                                 '[{}]'.format(href), Colors.ENDC)
                
        # pagination: icrement offset by 10 (max results per-query)
        offset += 10

        # save results to file
        save(finaljson)         

    return offset



if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    required_group = parser.add_argument_group('required arguments')
    options_group = parser.add_argument_group('options') 
    options = options_group.add_mutually_exclusive_group()

    required_group.add_argument('-t', '--type', dest='p_type', default='exploits', choices=['exploits','tools'], 
                    help='type of search, exploits vs tools.',required=True)    
    required_group.add_argument('-q', '--query', dest='query', 
                    help='search by keyword (e.g "wordpress 5.1")',required=True)                
    options.add_argument('-m', '--max', dest='max', default=10, type=int, 
                    help='retrieve MAX number of results.')
    options.add_argument('-a', '--view-all', dest='viewall', default=False, action='store_true', 
                    help='view all exploits found in a search, default is 10.')
    parser.add_argument('-s', '--sort', dest='sort', default='date', choices=['date','score'],
                     help='sort results by date or score.')        
    
    args = parser.parse_args()
    
    print(Colors.BANNER, 'Sploitus exploit searching for "{}"'.format(args.query), Colors.ENDC)        
    rs = search(query=args.query, sort=args.sort, p_type=args.p_type, check_all_exploits=args.viewall, _max=args.max)    
    