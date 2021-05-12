#! /usr/bin/env python

############## Attack Dump ############
### Dumps MITRE PRE ATT&CK Data to  ###
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

    for tactic in attack.preattack.tactics:
        tactic_obj = {'id':tactic.id,'name':tactic.name,'description':tactic.description}
        exported_tactics.append(tactic_obj)

    csv_fields = ['id','name','description']
    filename="preattack_tactics_"+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(exported_tactics)

    print("---->Tactic Export Complete<----")

def export_techniques():
    attack = Attck()
    exported_techniques=[]

    for technique in attack.preattack.techniques:
        tactics=[]
        for tactic in technique.tactics:
           tactic_obj=tactic.id
           tactics.append(tactic_obj)
        technique_obj = {'id':technique.id,'name':technique.name,'description':technique.description,'tactics':",".join(tactics)}
        exported_techniques.append(technique_obj)

    csv_fields = ['id','name','description','tactics']
    filename="preattack_techniques_"+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(exported_techniques)

    print("---->Technique Export Complete<----")


def export_actors():
    attack = Attck()
    exported_actors=[]

    for actor in attack.preattack.actors:
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
    filename="preattack_actors_"+datetime.now().strftime("%Y%m%d")+".csv"

    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(exported_actors)

    print("---->Actor Export Complete<----")

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

   tacticdump.join()
   techniquedump.join()
   actordump.join()
   
   print("-> Successfully Exported Mitre PreAtt&ck <-")

if __name__ == "__main__":
    sys.exit(main())

