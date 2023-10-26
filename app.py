from flask import Flask, render_template, request, session, redirect, url_for
import requests
import urllib3
import json
import getpass
import xml.etree.ElementTree as ET
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'fr1992'  # Set a secret key for session management

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form['username']
        password = request.form['password']


        # Send an HTTP request to your authentication endpoint
        auth_url = "https://100.70.0.20/api/?type=keygen&user=" + username + "&password=" + password # Replace with your authentication URL
        data = {
            "username": username,
            "password": password
        }
        
        response = requests.post(auth_url, data=data, verify=False)

        if response.status_code == 200:
            # Authentication successful
            root = ET.fromstring(response.content)
            key_element = root.find(".//key")
            api_key = key_element.text
            api_key_variable = api_key
            session['api_key'] = api_key
            session['username'] = username
            session['password'] = password
            
            return redirect(url_for('template_input'))
        else:
            return "Failed to authenticate. Response Code: " + str(response.status_code)
    except Exception as e:
        return "An error occurred: " + str(e)

@app.route('/template_input', methods=['GET', 'POST'])
def template_input():
    spoke = []
    if request.method == 'POST':
    
        template = request.form.get('template')
        template = template.split('\n')
        template = [x.strip() for x in template]
        
        coid = request.form['coid']
        cloud = request.form['cloud']
        gwprivate = request.form['gwprivate']
        gwpublic = request.form['gwpublic']
        public = request.form['public']
        private = request.form['private']
        
        spoke_input = request.form.get('spoke_input')
        spoke = spoke_input.split('\n')
        
        prjnum = request.form['prjnum']
        session['template'] = template
        session['coid'] = coid
        session['cloud'] = cloud
        session['gwprivate'] = gwprivate
        session['gwpublic'] = gwpublic
        session['private'] = private
        session['public'] = public
        session['spoke'] = spoke
        session['prjnum'] = prjnum

        return redirect(url_for('main_menu'))
    return render_template('template_input.html')
    
@app.route('/network', methods=['POST'])
def network(username, password, coid, cloud, template, dg, dg_parent, api_key_variable, gwprivate, gwpublic):
    try:
        username = session.get('username')
        password = session.get('password')
        coid = session.get('coid')
        cloud = session.get('cloud')
        template = session.get('template', [])
        api_key_variable = session.get('api_key')
        gwprivate = session.get('gwprivate')
        gwpublic = session.get('gwpublic')
  
        coid = coid.lower()
        cloud = cloud.lower()

        base_url = "https://100.70.0.20/restapi/v10.2/Network/EthernetInterfaces"

        if cloud == 'aws':
            for int1 in template:
                url = f"{base_url}?location=template&template=" + int1 + "&name=ethernet1/1"
                payload = {
                    "entry": {
                        "@name": "ethernet1/1",
                        "@template": int1,
                        "@vsys": "vsys1",
                        "ha": {}
                    }
                }

                headers = {
                    "Content-Type": "application/json"
                }

                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)

                print(f"Template: {int1}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
                
            
            for int2 in template:
                url = f"{base_url}?location=template&template="+int2+"&name=ethernet1/2"
        
                payload = {
                    "entry": {
                        "@name": "ethernet1/2",
                        "@template": int2,
                        "@vsys": "vsys1",
                        "layer3": {
                            "dhcp-client":{
                                "enable": "yes",
                                "create-default-route": "no"
                                },
                                "adjust-tcp-mss": {
                                "enable":"yes",
                                "ipv4-mss-adjustment":140
                                }
                                },
                        "comment":coid+"-external"
                    }
                }
        
                headers = {
                    "Content-Type": "application/json"
                }    
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
        
                print(f"Template: {int2}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
                
            for int3 in template:
                url = f"{base_url}?location=template&template="+int3+"&name=ethernet1/3"
        
                payload = {
                    "entry": {
                        "@name": "ethernet1/3",
                        "@template": int3,
                        "@vsys": "vsys1",
                        "layer3": {
                            "dhcp-client":{
                                "enable": "yes",
                                "create-default-route": "no"
                                },
                                "adjust-tcp-mss": {
                                "enable":"yes",
                                "ipv4-mss-adjustment":140
                                }
                                },
                        "comment":coid+"-internal"
                    }
                }
        
                headers = {
                    "Content-Type": "application/json"
                }    
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
        
                print(f"Template: {int3}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
        if cloud == 'azure':
            for int1 in template:
                url = f"{base_url}?location=template&template="+int1+"&name=ethernet1/3"
                payload = {
                        "entry": {
                            "@name": "ethernet1/3",
                            "@template": int1,
                            "@vsys": "vsys1",
                            "ha": {
        
                            }
                        }
                    }
        
                headers = {
                    "Content-Type": "application/json"
                }    
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
        
                print(f"Template: {int1}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
                
            ########## Public Interface - Azure ############
                
            for int2 in template:
                url = f"{base_url}?location=template&template="+int2+"&name=ethernet1/1"
        
                payload = {
                    "entry": {
                        "@name": "ethernet1/1",
                        "@template": int2,
                        "@vsys": "vsys1",
                        "layer3": {
                            "dhcp-client":{
                                "enable": "yes",
                                "create-default-route": "no"
                                },
                                "adjust-tcp-mss": {
                                "enable":"yes",
                                "ipv4-mss-adjustment":140
                                }
                                },
                        "comment":coid+"-external"
                    }
                }
        
                headers = {
                    "Content-Type": "application/json"
                }    
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
        
                print(f"Template: {int2}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
                
                
            ########## Private Interface - Azure ############
    
            for int3 in template:
                url = f"{base_url}?location=template&template="+int3+"&name=ethernet1/2"
        
                payload = {
                    "entry": {
                        "@name": "ethernet1/2",
                        "@template": int3,
                        "@vsys": "vsys1",
                        "layer3": {
                            "dhcp-client":{
                                "enable": "yes",
                                "create-default-route": "no"
                                },
                                "adjust-tcp-mss": {
                                "enable":"yes",
                                "ipv4-mss-adjustment":140
                                }
                                },
                        "comment":coid+"-internal"
                    }
                }
        
                headers = {
                    "Content-Type": "application/json"
                }    
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
        
                print(f"Template: {int3}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
        
        base_url = "https://100.70.0.20/restapi/v10.2/Device/VirtualSystems"        
        
        if cloud == 'aws':
            for vsys in template:
                url = f"{base_url}?location=template&template="+vsys+"&name=vsys1"
                
                payload = {
                    "entry": {
                        "@name": "vsys1",
                        "@template": vsys,
                        "import": {
                            "network":{
                                "interface":{
                                    "member": [
                                        "ethernet1/2",
                                        "ethernet1/3",
            
                                        ]
                                    }
                                    }
                                    }
                                    }
                                }
                headers = {
                    "Content-Type": "application/json"
                }
            
                response = requests.put(url, json=payload, headers=headers, auth=(username, password), verify=False)
                print(f"Template: {vsys}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
            
        if cloud == 'azure':
            for vsys in template:
                url = f"{base_url}?location=template&template="+vsys+"&name=vsys1"
                
                payload = {
                    "entry": {
                        "@name": "vsys1",
                        "@template": vsys,
                        "import": {
                            "network":{
                                "interface":{
                                    "member": [
                                        "ethernet1/1",
                                        "ethernet1/2",
            
                                        ]
                                    }
                                    }
                                    }
                                    }
                                }
                headers = {
                    "Content-Type": "application/json"
                }
            
                response = requests.put(url, json=payload, headers=headers, auth=(username, password), verify=False)
                print(f"Template: {vsys}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
                
        if cloud == 'aws':
            for zone1 in template:
                payload1 = json.dumps({
                    "entry": {
                        "@name": coid+"-internal",
                        "@location": "template",
                        "@template": zone1,
                        "@vsys": "vsys1",
                        "network": {
                            "layer3": {
                            "member":["ethernet1/3"]
                            }
                        }
                        }
                        })
                url = ("https://100.70.0.20/restapi/v10.2/Network/Zones?location=template&template="+zone1+"&vsys=vsys1&name="+coid+"-internal")
                headers = {
                'Content-Type': 'application/json',
                'X-PAN-KEY': api_key_variable
                }
                response1 = requests.request("POST", url, headers=headers, data=payload1, verify=False)
                print(zone1,"\n",response1.text,"\n")
                
            for zone2 in template:
                payload1 = json.dumps({
                    "entry": {
                        "@name": coid+"-external",
                        "@location": "template",
                        "@template": zone2,
                        "@vsys": "vsys1",
                        "network": {
                            "layer3": {
                            "member":["ethernet1/2"]
                            }
                        }
                        }
                        })
                url = ("https://100.70.0.20/restapi/v10.2/Network/Zones?location=template&template="+zone2+"&vsys=vsys1&name="+coid+"-external")
                headers = {
                'Content-Type': 'application/json',
                'X-PAN-KEY': api_key_variable
                } 
                response1 = requests.request("POST", url, headers=headers, data=payload1, verify=False)
                print(zone2,"\n",response1.text,"\n")
    
        if cloud == 'azure':
            for zone1 in template:
                payload1 = json.dumps({
                    "entry": {
                        "@name": coid+"-internal",
                        "@location": "template",
                        "@template": zone1,
                        "@vsys": "vsys1",
                        "network": {
                            "layer3": {
                            "member":["ethernet1/2"]
                            }
                        }
                        }
                        })
                url = ("https://100.70.0.20/restapi/v10.2/Network/Zones?location=template&template="+zone1+"&vsys=vsys1&name="+coid+"-internal")
                headers = {
                'Content-Type': 'application/json',
                'X-PAN-KEY': api_key_variable
                }
                response1 = requests.request("POST", url, headers=headers, data=payload1, verify=False)
                print(zone1,"\n",response1.text,"\n")             
                
            for zone2 in template:
                payload1 = json.dumps({
                    "entry": {
                        "@name": coid+"-external",
                        "@location": "template",
                        "@template": zone2,
                        "@vsys": "vsys1",
                        "network": {
                            "layer3": {
                            "member":["ethernet1/1"]
                            }
                        }
                        }
                        })
                url = ("https://100.70.0.20/restapi/v10.2/Network/Zones?location=template&template="+zone2+"&vsys=vsys1&name="+coid+"-external")
                headers = {
                'Content-Type': 'application/json',
                'X-PAN-KEY': api_key_variable
                }
                response1 = requests.request("POST", url, headers=headers, data=payload1, verify=False)
                print(zone2,"\n",response1.text,"\n")
                
        base_url = "https://100.70.0.20/restapi/v10.2/Network/VirtualRouters"
    
        #gwpublic=input("Put the IP of the Gateway in Public Subnet: ")
        #gwprivate=input("Put the IP of the Gateway in Private Subnet: ")
        
        print (gwpublic)
        print (gwprivate)
        
        if cloud == 'aws':
            for route in template:
                url = f"{base_url}?location=template&template="+route+"&name=default"
            
                payload = {
                    "entry": {
                        "@name": "default",
                        "@template": route,
                        "@vsys": "vsys1",
                        "interface": {
                            "member": [
                            "ethernet1/2",
                            "ethernet1/3"
                            ]
                        },
                        "routing-table": {
                        "ip": { 
                            "static-route": { 
                            
                                "entry":   [
                                    {
                                        "@name": "Default",
                                        "destination": "0.0.0.0/0",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwpublic
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        
                                {
            
                                        "@name": "RFC1918-a",
                                        "destination": "192.168.0.0/16",
                                        "interface": "ethernet1/3",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-b",
                                        "destination": "172.16.0.0/12",
                                        "interface": "ethernet1/3",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC6598",
                                        "destination": "100.70.0.0/15",
                                        "interface": "ethernet1/3",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-c",
                                        "destination": "10.0.0.0/8",
                                        "interface": "ethernet1/3",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        }
                                        ]
                                    
                                    }
                                }
                            }
                            
                                        
                        }
                    }
                
                headers = {
                    "Content-Type": "application/json"
                }
                
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
                
                print(f"Template: {route}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
            
        if cloud == 'azure':
            for route in template:
                url = f"{base_url}?location=template&template="+route+"&name=private"
            
                payload = {
                    "entry": {
                        "@name": "private",
                        "@template": route,
                        "@vsys": "vsys1",
                        "interface": {
                            "member": [
                            "ethernet1/2"
                            ]
                        },
                        "routing-table": {
                        "ip": { 
                            "static-route": { 
                            
                                "entry":   [
                                    {
                                        "@name": "Default",
                                        "destination": "0.0.0.0/0",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwpublic
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        
                                {
            
                                        "@name": "RFC1918-a",
                                        "destination": "192.168.0.0/16",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-b",
                                        "destination": "172.16.0.0/12",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "LB-Private",
                                        "destination": "168.63.129.16/32",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },                                
                                        {
            
                                        "@name": "RFC6598",
                                        "destination": "100.70.0.0/15",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-c",
                                        "destination": "10.0.0.0/8",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        }
                                        ]
                                    
                                    }
                                }
                            }
                            
                                        
                        }
                    }
                
                headers = {
                    "Content-Type": "application/json"
                }
                
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
                
                print(f"Template: {route}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
            
            
            for route in template:
                url = f"{base_url}?location=template&template="+route+"&name=public"
            
                payload = {
                    "entry": {
                        "@name": "public",
                        "@template": route,
                        "@vsys": "vsys1",
                        "interface": {
                            "member": [
                            "ethernet1/1"
                            ]
                        },
                        "routing-table": {
                        "ip": { 
                            "static-route": { 
                            
                                "entry":   [
                                    {
                                        "@name": "Default",
                                        "destination": "0.0.0.0/0",
                                        "interface": "ethernet1/1",
                                        "nexthop": {
                                            "ip-address": gwpublic
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        
                                {
            
                                        "@name": "RFC1918-a",
                                        "destination": "192.168.0.0/16",
                                        "nexthop": {
                                            "next-vr": "private"
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-b",
                                        "destination": "172.16.0.0/12",
                                        "nexthop": {
                                            "next-vr": "private"
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                    {
                                        "@name": "LB-Public",
                                        "destination": "168.63.129.16/32",
                                        "interface": "ethernet1/1",
                                        "nexthop": {
                                            "ip-address": gwpublic
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },                              
                                        {
            
                                        "@name": "RFC6598",
                                        "destination": "100.70.0.0/15",
                                        "nexthop": {
                                            "next-vr": "private"
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-c",
                                        "destination": "10.0.0.0/8",
                                        "nexthop": {
                                            "next-vr": "private"
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        }
                                        ]
                                    
                                    }
                                }
                            }
                            
                                        
                        }
                    }
                
                headers = {
                    "Content-Type": "application/json"
                }
                
                response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
                
                print(f"Template: {route}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
            
            
            for route in template:
                url = f"{base_url}?location=template&template="+route+"&name=private"
            
                payload = {
                    "entry": {
                        "@name": "private",
                        "@template": route,
                        "@vsys": "vsys1",
                        "interface": {
                            "member": [
                            "ethernet1/2"
                            ]
                        },
                        "routing-table": {
                        "ip": { 
                            "static-route": { 
                            
                                "entry":   [
                                    {
                                        "@name": "Default",
                                        "destination": "0.0.0.0/0",
                                        "nexthop": {
                                            "next-vr": "public"
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        
                                {
            
                                        "@name": "RFC1918-a",
                                        "destination": "192.168.0.0/16",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-b",
                                        "destination": "172.16.0.0/12",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "LB-Private",
                                        "destination": "168.63.129.16/32",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },                                
                                        {
            
                                        "@name": "RFC6598",
                                        "destination": "100.70.0.0/15",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        },
                                        {
            
                                        "@name": "RFC1918-c",
                                        "destination": "10.0.0.0/8",
                                        "interface": "ethernet1/2",
                                        "nexthop": {
                                            "ip-address": gwprivate
                                            },
                                        "admin-dist": 10,
                                        "metric": 10
                                        }
                                        ]
                                    
                                    }
                                }
                            }
                            
                                        
                        }
                    }
                
                headers = {
                    "Content-Type": "application/json"
                }
                
                response = requests.put(url, json=payload, headers=headers, auth=(username, password), verify=False)
                
                print(f"Template: {route}")
                print(f"Response Code: {response.status_code}")
                print(f"Response Content: {response.content.decode('utf-8')}")
              

        return "Network configuration complete"  # Adjust the response as needed
    except Exception as e:
        return "An error occurred: " + str(e)  # Handle errors gracefully

@app.route('/security', methods=['POST'])
def sec_profiles(username,password,coid,cloud,template,dg,dg_parent,api_key_variable):
    try:
        
        username = session.get('username')
        password = session.get('password')
        coid = session.get('coid')
        cloud = session.get('cloud')
        template = session.get('template')
        api_key_variable = session.get('api_key')
        gwprivate = session.get('gwprivate')
        gwpublic = session.get('gwpublic')
  
        cloud = cloud.lower()

        coid=coid.upper()
        ########### Antispyware Profile ###########
    
        base_url = "https://100.70.0.20/restapi/v10.2/Objects/AntiSpywareSecurityProfiles"
        
        for asp in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"-ASP"
                
            payload = {
                "entry": {
                    "@name": coid+"-ASP",
                    "@template": dg,
                    "rules": {
                            "entry": [
                                {
                                    "@name":"simple-critical",
                                    "threat-name":"any",
                                    "category":"any",
                                    "severity": {
                                        "member": [
                                            "critical"
                                            ]
                                        },
                                    "action": {
                                        "drop" :{}
                                        },
                                    "packet-capture": "extended-capture"
                                    },
                                    
                                {
                                    "@name":"simple-high",
                                    "threat-name":"any",
                                    "category":"any",
                                    "severity": {
                                        "member": [
                                            "high"
                                            ]
                                        },
                                    "action": {
                                        "drop" :{}
                                        },
                                    "packet-capture": "extended-capture"
                                    },                     
                                {
                                    "@name":"simple-medium",
                                    "threat-name":"any",
                                    "category":"any",
                                    "severity": {
                                        "member": [
                                            "medium"
                                            ]
                                        },
                                    "action": {
                                        "default" :{}
                                        },
                                    "packet-capture": "single-packet"
                                    },
                                {
                                    "@name":"simple-low",
                                    "threat-name":"any",
                                    "category":"any",
                                    "severity": {
                                        "member": [
                                            "low"
                                            ]
                                        },
                                    "action": {
                                        "alert" :{}
                                        },
                                    "packet-capture": "disable"
                                    }                       
                                ]
                                },
                                    
                        "cloud-inline-analysis":"no",
                        "botnet-domains": {
                            "whitelist": {
                                "entry": [
                                    {
                                        "@name":"protera.com"
                                    },
                                    {
                                        "@name":"tanium.com"
                                    }
                                    ]
                                }
                                }
                }
            }
            
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}")
            
            
        ########### Vulnerability Profile ###########
    
        base_url = "https://100.70.0.20/restapi/v10.2/Objects/VulnerabilityProtectionSecurityProfiles"
    
        for vuln in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"-VP"
                
            payload = {
                "entry": {
                    "@name": coid+"-VP",
                    "@template": dg,
                    "rules": {
                            "entry": [
                                {
                                    "@name":"simple-client-critical",
                                    "threat-name":"any",
                                    "host":"client",
                                    "category":"any",
                                    "packet-capture": "extended-capture",
                                    "severity": {
                                        "member": [
                                            "critical"
                                            ]
                                        },
                                    "cve": {
                                        "member": [
                                            "any"
                                            ]
                                        },
                                    "vendor-id": {
                                        "member": [
                                            "any"
                                            ]
                                        },                               
                                    "action": {
                                        "drop" :{}
                                        },
                                    },
                                    
                                {
                                    "@name":"simple-client-high",
                                    "threat-name":"any",
                                    "host":"client",
                                    "category":"any",
                                    "packet-capture": "extended-capture",
                                    "severity": {
                                        "member": [
                                            "high"
                                            ]
                                        },
                                    "cve": {
                                        "member": [
                                            "any"
                                            ]
                                        },
                                    "vendor-id": {
                                        "member": [
                                            "any"
                                            ]
                                        },                               
                                    "action": {
                                        "drop" :{}
                                        },
                                    },
                                {
                                    "@name":"simple-client-medium",
                                    "threat-name":"any",
                                    "host":"client",
                                    "category":"any",
                                    "packet-capture": "single-packet",
                                    "severity": {
                                        "member": [
                                            "medium"
                                            ]
                                        },
                                    "cve": {
                                        "member": [
                                            "any"
                                            ]
                                        },
                                    "vendor-id": {
                                        "member": [
                                            "any"
                                            ]
                                        },                               
                                    "action": {
                                        "default" :{}
                                        },
                                    },
                                {
                                    "@name":"simple-server-critical",
                                    "threat-name":"any",
                                    "host":"server",
                                    "category":"any",
                                    "packet-capture": "extended-capture",
                                    "severity": {
                                        "member": [
                                            "critical"
                                            ]
                                        },
                                    "cve": {
                                        "member": [
                                            "any"
                                            ]
                                        },
                                    "vendor-id": {
                                        "member": [
                                            "any"
                                            ]
                                        },                               
                                    "action": {
                                        "drop" :{}
                                        },
                                    },                       
                                {
                                    "@name":"simple-server-high",
                                    "threat-name":"any",
                                    "host":"server",
                                    "category":"any",
                                    "packet-capture": "extended-capture",
                                    "severity": {
                                        "member": [
                                            "high"
                                            ]
                                        },
                                    "cve": {
                                        "member": [
                                            "any"
                                            ]
                                        },
                                    "vendor-id": {
                                        "member": [
                                            "any"
                                            ]
                                        },                               
                                    "action": {
                                        "drop" :{}
                                        },
                                    },
                                {
                                    "@name":"simple-server-medium",
                                    "threat-name":"any",
                                    "host":"server",
                                    "category":"any",
                                    "packet-capture": "single-packet",
                                    "severity": {
                                        "member": [
                                            "medium"
                                            ]
                                        },
                                    "cve": {
                                        "member": [
                                            "any"
                                            ]
                                        },
                                    "vendor-id": {
                                        "member": [
                                            "any"
                                            ]
                                        },                               
                                    "action": {
                                        "default" :{}
                                        },
                                    }
                                ]
                                }
                                }
                            }
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}")
            
            
        ########### URL Custom Profile Creation ###########
    
    
        base_url = "https://100.70.0.20/restapi/v10.2/Objects/CustomURLCategories"
    
        for curl in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"_EXTERNAL_URL_FILTER"
                
            payload = {
                "entry": {
                    "@name": coid+"_EXTERNAL_URL_FILTER",
                    "@template": dg,
                    "list":{
                        "member": [
                                "protera.com"
                                ]
                            },
                    "type":"URL List"
                    }
                    }
                    
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}")
        
        ###### URL Security Profile #####
        
        base_url = "https://100.70.0.20/restapi/v10.2/Objects/URLFilteringSecurityProfiles"
        
        for url in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"_DEF_CONTENT_CATEGORY"
                
            payload = {
                "entry": {
                    "@name": coid+"_DEF_CONTENT_CATEGORY",
                    "@template": dg,
                    "local-inline-cat": "yes",
                    "cloud-inline-cat": "no",
                    "allow": {
                        "member": [
                            coid+"_EXTERNAL_URL_FILTER"
                            ]
                        },
                    "block": {
                        "member": [
                            "MSP_BLOCK_URL_FILTER_LIST",
                            "abortion",
                            "adult",
                            "command-and-control",
                            "cryptocurrency",
                            "extremism",
                            "gambling",
                            "hacking",
                            "high-risk",
                            "malware",
                            "nudity",
                            "phishing",
                            "questionable",
                            "ransomware",
                            "sex-education"
                            ]
                        },
                    "alert": {
                        "member": [
                            "medium-risk",
                            "newly-registered-domain",
                            "parked",
                            "peer-to-peer",
                            "proxy-avoidance-and-anonymizers",
                            "real-time-detection",
                            "shareware-and-freeware",
                            "unknown"
                            ]
                        },
                    "credential-enforcement": {
                        "mode": {
                            "disabled":{}
                            },
                        "log-severity": "medium",
                        "allow": {
                            "member": [
                                coid+"_EXTERNAL_URL_FILTER"
                                ]
                            },
                        "block": {
                            "member": [
                                "MSP_BLOCK_URL_FILTER_LIST",
                                "abortion",
                                "adult",
                                "command-and-control",
                                "cryptocurrency",
                                "extremism",
                                "gambling",
                                "hacking",
                                "high-risk",
                                "malware",
                                "nudity",
                                "phishing",
                                "questionable",
                                "ransomware",
                                "sex-education"
                                ]
                        }
                        }
                        }
                    }
                            
                            
            
                    
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}")
            
        ########### WildFire Profile Creation ###########
    
        base_url = "https://100.70.0.20/restapi/v10.2/Objects/WildFireAnalysisSecurityProfiles"
    
        for wlf in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"_WILDFIRE"
                
            payload = {
                "entry": {
                    "@name": coid+"_WILDFIRE",
                    "@template": dg,
                    "rules":{
                        "entry": [
                            {
                                "@name": "default",
                                "application": {
                                    "member": [
                                        "any"
                                        ]
                                    },
                                "file-type": {
                                    "member": [
                                        "any"
                                        ]
                                    },
                                "direction" : "both",
                                "analysis" : "public-cloud"
                                }
                            ]
                            }
                            }
                            }
                                
            
                    
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}")
        
        ########### Security Profile Groups ###########
        
        
                    #### INTERNAL SPG####
                    
        base_url = "https://100.70.0.20/restapi/v10.2/Objects/SecurityProfileGroups"
        
        for sgroup1 in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"_INTERNAL_SPG"
                
            payload = {
                "entry": {
                    "@name": coid+"_INTERNAL_SPG",
                    "@template": dg,
                    "spyware": {
                        "member": [
                            coid+"-ASP"
                            ]
                        },
                    "vulnerability": {
                        "member": [
                            coid+"-VP"
                            ]
                        }
                        }
                        }
                        
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}")
                    
                    ### External IN SPG ###
                    
        for sgroup2 in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"_EXTERNAL_IN_SPG"
                
            payload = {
                "entry": {
                    "@name": coid+"_EXTERNAL_IN_SPG",
                    "@template": dg,
                    "spyware": {
                        "member": [
                            coid+"-ASP"
                            ]
                        },
                    "wildfire-analysis": {
                        "member": [
                            coid+"_WILDFIRE"
                            ]
                        },
                    "vulnerability": {
                        "member": [
                            coid+"-VP"
                            ]
                        }
                        }
                        }
                        
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}")
                    
                    ### External OUT SPG ###
                    
        for sgroup3 in template:
            url = f"{base_url}?location=device-group&device-group="+dg+"&name="+coid+"_EXTERNAL_OUT_SPG"
                
            payload = {
                "entry": {
                    "@name": coid+"_EXTERNAL_OUT_SPG",
                    "@template": dg,
                    "spyware": {
                        "member": [
                            coid+"-ASP"
                            ]
                        },
                    "wildfire-analysis": {
                        "member": [
                            coid+"_WILDFIRE"
                            ]
                        },
                    "url-filtering": {
                        "member": [
                            coid+"_DEF_CONTENT_CATEGORY"
                            ]
                        },
                    "vulnerability": {
                        "member": [
                            coid+"-VP"
                            ]
                        }
                        }
                        }
                        
            headers = {
                "Content-Type": "application/json"
            }
            
            response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
            
            print(f"Template: {dg}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Content: {response.content.decode('utf-8')}") 

    except Exception as e:
        return "An error occurred: " + str(e)            

@app.route('/address', methods=['POST'])
def address(username,password,coid,cloud,template,dg,dg_parent,api_key_variable, spoke):
    
        
    username = session.get('username')
    password = session.get('password')
    coid = session.get('coid')
    cloud = session.get('cloud')
    template = session.get('template')
    api_key_variable = session.get('api_key')
    gwprivate = session.get('gwprivate')
    gwpublic = session.get('gwpublic')
    public = session.get('public')
    private = session.get('private')
    spoke = session.get('spoke', [])
  
    cloud = cloud.lower()

    coid=coid.upper()
    
    prvpure = private.rpartition('/')[0]
    prvmask = private.rpartition('/')[2]
    
    pubpure = public.rpartition('/')[0]
    pubmask = public.rpartition('/')[2]
    
    prvname = "n."+prvpure+"_"+prvmask
    pubname = "n."+pubpure+"_"+pubmask
    
    print (prvname) 
    
    base_url = "https://100.70.0.20/restapi/v10.2/Objects/Addresses"
    
    url = f"{base_url}?location=device-group&device-group="+dg_parent+"&name="+prvname
    
    payload = {
        "entry": {
            "@name": prvname,
            "@template": dg_parent,
            "ip-netmask" : private
            }
        }
        
    headers = {
        "Content-Type": "application/json"
    }
    
    response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
    
    print(f"Template: {dg_parent}")
    print(f"Response Code: {response.status_code}")
    print(f"Response Content: {response.content.decode('utf-8')}")
        
    url = f"{base_url}?location=device-group&device-group="+dg_parent+"&name="+pubname
    
    payload = {
        "entry": {
            "@name": pubname,
            "@template": dg_parent,
            "ip-netmask" : public
            }
        }
        
    headers = {
        "Content-Type": "application/json"
    }
    
    response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
    
    print(f"Template: {dg_parent}")
    print(f"Response Code: {response.status_code}")
    print(f"Response Content: {response.content.decode('utf-8')}")
    
    
                ### Create the COID INTERFACE NETWORK Group ####
    
    
    base_url = "https://100.70.0.20/restapi/v10.2/Objects/AddressGroups"
    
    url = f"{base_url}?location=device-group&device-group="+dg_parent+"&name="+coid+"_INTERFACE_NETWORKS"
    
    payload = {
        "entry": {
            "@name": coid+"_INTERFACE_NETWORKS",
            "@template": dg_parent,
            "static" : {
                "member" : [
                    prvname,
                    pubname
                    ]
                }
            }
        }
        
    headers = {
        "Content-Type": "application/json"
    }
    
    response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
    
    print(f"Template: {dg_parent}")
    print(f"Response Code: {response.status_code}")
    print(f"Response Content: {response.content.decode('utf-8')}")
    
    for spokes in spoke:
        print (spokes)
    
    spoke = [x.strip() for x in spoke]
    
    base_url = "https://100.70.0.20/restapi/v10.2/Objects/Addresses"
    spoke_networks = []
    for x in spoke:
        xpure = x.rpartition('/')[0]
        xmask = x.rpartition('/')[2]
        xname = "s."+xpure+"_"+xmask
        url = f"{base_url}?location=device-group&device-group="+dg_parent+"&name="+xname
        
        payload = {
            "entry": {
                "@name": xname,
                "@template": dg_parent,
                "ip-netmask" : x
                }
            }
            
        headers = {
            "Content-Type": "application/json"
        }
    
        response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
        spoke_networks.append(xname)
        print(f"Template: {x}")
        print(f"Response Code: {response.status_code}")
        print(f"Response Content: {response.content.decode('utf-8')}")
        
    base_url = "https://100.70.0.20/restapi/v10.2/Objects/AddressGroups"   
    url = f"{base_url}?location=device-group&device-group="+dg_parent+"&name="+coid+"_CLOUD_NETWORKS"
    
    payload = {
        "entry": {
            "@name": coid+"_CLOUD_NETWORKS",
            "@template": dg_parent,
            "static": {
                "member": []
            }
        }
    }
    
    for interface in spoke_networks:
        payload["entry"]["static"]["member"].append(interface)
    
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers, auth=(username, password), verify=False)
    
    print(f"Template: {dg_parent}")
    print(f"Response Code: {response.status_code}")
    print(f"Response Content: {response.content.decode('utf-8')}")


@app.route('/policies', methods=['POST'])
def policies(username,password,coid,cloud,template,dg,dg_parent,api_key_variable):
    
        
    username = session.get('username')
    password = session.get('password')
    coid = session.get('coid')
    cloud = session.get('cloud')
    template = session.get('template')
    api_key_variable = session.get('api_key')
    gwprivate = session.get('gwprivate')
    gwpublic = session.get('gwpublic')
    public = session.get('public')
    private = session.get('private')
    spoke = session.get('spoke', [])
    prjnum = session.get('prjnum')

    coid=coid.upper()
    PANORAMA_IP = '100.70.0.20' 
    DEVICE_GROUP = dg
    POLICY_NAME = prjnum+'_'+coid+'_PING_ONLY'
    SOURCE_ZONE =coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    APPLICATIONS = ['icmp', 'traceroute', 'ping']
    ACTION = 'allow'
    API_KEY = api_key_variable
        
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <service><member>application-default</member></service>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application>
            {applications}
        </application>
        <action>{action}</action>
        <description>Internal Ping to All</description>
        <tag><member>INTERNAL_POLICY</member></tag>
    </entry>
    """
    
    # Construct the applications XML
    applications_xml = '\n'.join([f'<member>{app}</member>' for app in APPLICATIONS])
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        applications=applications_xml,
        action=ACTION
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
        
    #######INTERNET-TO-APP-BASED###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_INTERNET_APP_BASED'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-external'
    ACTION = 'allow'
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <service><member>any</member></service>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>PROT_INTERNET_SHARED_APP_GROUP</member></application>
        <action>{action}</action>
        <description>Internet APP Based</description>
        <tag><member>EXTERNAL_POLICY</member></tag>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######INTERNET-SERVICE-BASED###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_INTERNET_SERVICE_BASED'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-external'
    ACTION = 'allow'
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <service><member>PROT_INTERNET_SHARED_SERVICE_GROUP</member></service>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <action>{action}</action>
        <description>Internet Service Based</description>
        <tag><member>EXTERNAL_POLICY</member></tag>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######INTERNET-URL-BASED###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_INTERNET_URL_BASED'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-external'
    ACTION = 'allow'
    url_filter_policy = coid.upper()+"_EXTERNAL_URL_FILTER"
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>{action}</action>
        <category>
            <member>MSP_ALLOW_URL_FILTER_LIST</member>
            <member>{url_filter_policy1}</member>
        </category>
        <description>Internet URL Based</description>
        <tag><member>EXTERNAL_POLICY</member></tag>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION,
        url_filter_policy1=url_filter_policy
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######INTERNET-COUNTRY-BASED###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_INTERNET_COUNTRY_BASED'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-external'
    ACTION = 'allow'
    SEC_PROFILE = coid.upper()+"_EXTERNAL_OUT_SPG"
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination>
            <member>CA</member>
            <member>US</member>
        </destination>
        <application>
            <member>PROTERA_DEFAULT_TO_INTERNET</member>
            <member>PROTERA_LINUX_PACKAGE_INSTALL</member>       
        </application>
        <service><member>application-default</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>Internet URL Based</description>
        <tag><member>EXTERNAL_POLICY</member></tag>
        <profile-setting>
            <group>
                <member>{sec_profile}</member>
            </group>
        </profile-setting>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION,
        sec_profile=SEC_PROFILE
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######PROTERA-TO-COID###########
    
    POLICY_NAME = prjnum+'_'+'PROTERA_TO_'+coid
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    ACTION = 'allow'
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>PROT_MANAGEMENT_ADDRESS_GROUP</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>Protera to customer</description>
        <tag><member>MGMT_POLICY</member></tag>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######COID-TO-PROTERA###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_PROTERA'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    ACTION = 'allow'
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>PROT_MANAGEMENT_ADDRESS_GROUP</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>Protera to customer</description>
        <tag><member>MGMT_POLICY</member></tag>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    
    #######COID-TO-DEVO###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_DEVO'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    ACTION = 'allow'
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>DEVO_SEIM_SERVICE_GROUP</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>COID to Devo</description>
        <tag><member>INTERNAL_POLICY</member></tag>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    
    #######TO-LB###########
    
    POLICY_NAME = prjnum+'_'+coid+'_LB_HEALTH_CHECK'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    ACTION = 'allow'
    INTERFACE_NETWORKS = coid.upper()+"_INTERFACE_NETWORKS"
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>CLOUD_LB_HEALTH_CHECK_ADDRESS_GROUP</member></source>
        <destination><member>{interface_networks}</member></destination>
        <application>
            <member>ssl</member>
            <member>web-browsing</member>
        </application>
        <service><member>application-default</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>LB-Health-Check</description>
        <tag><member>MGMT_POLICY</member></tag>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION,
        interface_networks=INTERFACE_NETWORKS
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######TO-LM###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_LM'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    ACTION = 'allow'
    CLOUD_NETWORKS=coid.upper()+"_CLOUD_NETWORKS"
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{destination_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>{cloud_networks}</member></destination>
        <application><member>any</member></application>
        <service><member>application-default</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>LB-Health-Check</description>
        <tag><member>INTERNAL_POLICY</member></tag>
        <disabled>yes</disabled>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION,
        cloud_networks=CLOUD_NETWORKS
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######TO-COMMV###########
    
    POLICY_NAME = prjnum+'_'+coid+'_TO_COMMV'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    ACTION = 'allow'
    CLOUD_NETWORKS=coid.upper()+"_CLOUD_NETWORKS"
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>{source_zone}</member></from>
        <to><member>{source_zone}</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>tcp-8403</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>COID_TO_COMMV</description>
        <tag><member>INTERNAL_POLICY</member></tag>
        <disabled>yes</disabled>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION,
        cloud_networks=CLOUD_NETWORKS
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)
    
    #######REMOTE-TO-SAP###########
    
    POLICY_NAME = prjnum+'_'+coid+'_REMOTE_TO_SAP'
    SOURCE_ZONE = coid.lower()+'-internal'
    DEST_ZONE = coid.lower()+'-internal'
    ACTION = 'allow'
    SEC_PROFILE = coid.upper()+"_INTERNAL_SPG"
    
    # XML template
    policy_xml_template = """
    <entry name="{policy_name}">
        <log-setting>DEFAULT_LOG_FORWARD</log-setting>
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>SAP_ACCESS_PORT_GROUP</member></service>
        <action>{action}</action>
        <category><member>any</member></category>
        <description>REMOTE-TO-SAP</description>
        <tag><member>INTERNAL_POLICY</member></tag>
        <disabled>yes</disabled>
        <profile-setting>
            <group>
                <member>{sec_profile}</member>
            </group>
        </profile-setting>
        
    </entry>
    """
    
    
    # Construct the XML payload
    policy_xml = policy_xml_template.format(
        policy_name=POLICY_NAME,
        source_zone=SOURCE_ZONE,
        destination_zone=DEST_ZONE,
        action=ACTION,
        sec_profile=SEC_PROFILE
    )
    
    # URL for the API request
    url = f'https://{PANORAMA_IP}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name="{DEVICE_GROUP}"]/pre-rulebase/security/rules&key={API_KEY}'
    
    # Headers for the request
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    # Data for the request
    data = {'element': policy_xml}
    
    # Send the POST request
    response = requests.post(url, headers=headers, data=data, verify=False)
    
    # Print the response
    print(response.status_code)
    print(response.text)

@app.route('/main_menu', methods=['GET', 'POST'])
def main_menu():
    username = session.get('username')
    password = session.get('password')
    coid = session.get('coid')
    cloud = session.get('cloud')
    template = session.get('template', [])
    api_key_variable = session.get('api_key')
    gwprivate = session.get('gwprivate')
    gwpublic = session.get('gwpulic')
    spoke = session.get('spoke', [])
    prjnum = session.get('prjnum')
    
    if cloud == 'azure':
        cloud_sym='AZ'
    elif cloud == 'aws':
        cloud_sym='AWS'
        
    dg = coid.upper()+"-"+cloud_sym
    dg_parent = coid.upper()

    if request.method == 'POST':
        choice = request.form['choice']
        if choice == '1':
            network(username, password, coid, cloud, template, dg, dg_parent, api_key_variable, gwprivate, gwpublic)
            sec_profiles(username, password, coid, cloud, template, dg, dg_parent, api_key_variable)
            address(username, password, coid, cloud, template, dg, dg_parent, api_key_variable,spoke)
            policies(username, password, coid, cloud, template, dg, dg_parent, api_key_variable)
        elif choice == '2':
            network(username, password, coid, cloud, template, dg, dg_parent, api_key_variable, gwprivate, gwpublic)
        elif choice == '3':
            sec_profiles(username, password, coid, cloud, template, dg, dg_parent, api_key_variable)
            address(username, password, coid, cloud, template, dg, dg_parent, api_key_variable,spoke)
            policies(username, password, coid, cloud, template, dg, dg_parent, api_key_variable)
        elif choice == '4':
            print("May the Force be with You")

    return render_template('main_menu.html', username=username, coid=coid, cloud=cloud, template=template, api_key_variable=api_key_variable, dg=dg, dg_parent=dg_parent, gwprivate=gwprivate, gwpublic=gwpublic, spoke=spoke)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8088)



