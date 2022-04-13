#! /usr/bin/env python

############## Attack Dump ############
### Dumps MITRE ATT&CK Data to      ###
###     current directory           ###
#######################################
############# Requirements ############
### Install pyattack before running ###
### [Optional] Create virtualenv    ###
### pip install pyattack            ###
#######################################
############## Versions ###############
##### 20200826 - Initial Version  #####
#######################################

from pyattck import Attck
import sys
import csv
from datetime import datetime
import threading

def export_tactics():
    attack = Attck()
    exported_tactics=[]

    for tactic in attack.enterprise.tactics:
        tactic_obj = {'id':tactic.id,'name':tactic.name,'description':tactic.description}
        exported_tactics.append(tactic_obj)

    csv_fields = ['id','name','description']
    filename="attack_tactics_"+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(exported_tactics)

    print("---->Tactic Export Complete<----")

def export_mitigations():
    attack = Attck()
    exported_mitigations=[]

    for mitigation in attack.enterprise.mitigations:
        techlist=[]
        for technique in mitigation.techniques:
            techlist_obj=technique.id
            techlist.append(techlist_obj)
        mitigation_obj = {'id': mitigation.id, 'name': mitigation.name, 'type':mitigation.type,'description': mitigation.description, 'techniques':",".join(techlist)}
        exported_mitigations.append(mitigation_obj)

    csv_fields = ['id','name','type','description','techniques']
    filename="attack_mitigations_"+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
       writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
       writer.writeheader()
       writer.writerows(exported_mitigations)

    print("---->Mitigation Export Complete<----")

def export_techniques():
    attack = Attck()
    exported_techniques=[]

    for technique in attack.enterprise.techniques:
        tactics=[]
        platforms=[]
        for tactic in technique.tactics:
           tactic_obj=tactic.id
           tactics.append(tactic_obj)
        platform = technique.platforms
        if isinstance(platform, list):
            platform=platform
        else: 
            platform=[]
        datasource = technique.data_sources
        if isinstance(datasource, list):
          datasource=datasource
        else:
          datasource=[]
        technique_obj = {'id':technique.id,'name':technique.name,'description':technique.description,'platforms':",".join(platform),'data_source':",".join(datasource),'tactics':",".join(tactics)}
        exported_techniques.append(technique_obj)

    csv_fields = ['id','name','description','platforms','data_source','tactics']
    filename="attack_techniques_"+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(exported_techniques)

    print("---->Technique Export Complete<----")


def export_actors():
    attack = Attck()
    exported_actors=[]

    for actor in attack.enterprise.actors:
        techlist=[]
        for technique in actor.techniques:
            techlist_obj=technique.id
            techlist.append(techlist_obj)
        if isinstance(actor.country, list):
          country = actor.country
        else:
          country = []
        actor_obj = {'id':actor.id,'name':actor.name,'description':actor.description, 'country':",".join(country),'techniques':",".join(techlist)}
        exported_actors.append(actor_obj)

    csv_fields = ['id','name','description','country','techniques']
    filename="attack_actors_"+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(exported_actors)

    print("---->Actor Export Complete<----")


def export_tools():
    attack = Attck()
    exported_tools=[]
    
    # Export Tools
    for tool in attack.enterprise.tools:
      techlist=[]
      actorlist=[]
      for technique in tool.techniques:
        techlist_obj=technique.id
        techlist.append(techlist_obj)
      for actor in tool.actors:
        actor_obj=actor.id
        actorlist.append(actor_obj)
      tool_obj = {'id':tool.id,'name':tool.name,'description':tool.description,'type':"tool",'techniques':",".join(techlist),'actors':",".join(actorlist)}
      exported_tools.append(tool_obj)


    for malware in attack.enterprise.malwares:
      techlist=[]
      actorlist=[]
      for technique in tool.techniques:
        techlist_obj=technique.id
        techlist.append(techlist_obj)
      for actor in tool.actors:
        actor_obj=actor.id
        actorlist.append(actor_obj)
      platform = malware.platforms
      if isinstance(platform, list):
        platform=platform
      else: 
        platform=[]
      malware_obj = {'id':malware.id,'name':malware.name,'description':malware.description,'type':"malware",'techniques':",".join(techlist),'actors':",".join(actorlist), 'platforms':",".join(platform)}
      exported_tools.append(malware_obj)

    csv_fields = ['id','name','description','type','techniques','actors','platforms']
    filename='attack_tools_'+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(exported_tools)

    print("---->Tool Export Complete<----")

def main():

   # Dump Mitre Tactics
   print("-->Dumping Tactics<--")
   tacticdump = threading.Thread(target=export_tactics)
   tacticdump.start()

   # Dump Mitre Techniques
   print("-->Dumping Techniques<--")
   techniquedump = threading.Thread(target=export_techniques)
   techniquedump.start()

   # Dump Mitre Actors
   print("-->Dumping Actors<--")
   actordump = threading.Thread(target=export_actors)
   actordump.start()

   # Dump Mitre Software
   print("-->Dumping Software<--")
   softwaredump = threading.Thread(target=export_tools)
   softwaredump.start()

   # Dump Mitre Mitigations
   print("-->Dumpint Mitigations<--")
   mitigationdump = threading.Thread(target=export_mitigations)
   mitigationdump.start()


   tacticdump.join()
   techniquedump.join()
   actordump.join()
   softwaredump.join()
   mitigationdump.join()

   print("-> Successfully Exported Mitre Att&ck <-")

if __name__ == "__main__":
    sys.exit(main())

