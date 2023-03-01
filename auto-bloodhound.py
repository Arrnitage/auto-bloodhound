import sys
import requests

# run it on bash: echo -n 'neo4j:<PASSWORD>' | base64
AUTHORIZATION = "bmVvNGo6Ymxvb2Rob3VuZA=="
NEO4J_DB = "http://localhost:7474"
NEO4J_API = NEO4J_DB + "/db/data/transaction/commit"

def send(cql:str) -> dict:
        headers = {
            "Authorization": AUTHORIZATION,
            "accept": "application/json; charset=UTF-8",
            "content-type": "application/json"
        }
        body = {"statements":[{ "statement": cql}]}
        resp = requests.post(url=NEO4J_API, headers=headers, json=body)
        print(resp.text)
        return resp.json()


def clear():
    cql = "MATCH (n) DETACH DELETE n"
    send(cql)

def sugg():
    strategy = {
        "Kerberoast": {
            "cmd": 'MATCH (u:User) WHERE u.hasspn=TRUE RETURN u', 
            "operate": "Rubeus.exe kerberoast"
        },
        "AS-REP_Roast": {
            "cmd": 'MATCH (u:User {dontreqpreauth: true}) RETURN u', 
            "operate": "impacket-GetNPUsers <DOMAIN> -userfile users.txt -format hashcat -outputfile as-rep-roast.hash -dc-ip <DC_IP>"
        },
        "Sensitive_ACL": {
            "cmd": 'MATCH p=(u {owned: true})-[r1]->(n) WHERE r1.isacl=true RETURN p', 
            "operate": ""
        },
        "Unconstrained_Delegation": {
            "cmd": 'MATCH (c:Computer {unconstraineddelegation:true}) return c', 
            "operate": ""
        },
        "Sensitive_Rights": {
            "cmd": 'MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p', 
            "operate": ""
        }
    }
    for k in strategy.keys():
        realname = k.replace("_", " ")
        print("[+] Strategy: {name}".format(name=realname))
        print("[+] Command: {command}".format(command=strategy[k].get("cmd")))
        print("[+] Operate: {operate}".format(operate=strategy[k].get("operate")))
        send(strategy[k].get("cmd"))
        print("\n=======================================")


if __name__ == '__main__':
    option = sys.argv[1]
    if option == "clear":
        clear()

    if option == "sugg":
        sugg()