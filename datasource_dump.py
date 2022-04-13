from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Collection
import csv

from datetime import datetime
import sys

collections = {"enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e"}

collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections['enterprise_attack']}/")
src = TAXIICollectionSource(collection)

exported_datasources = []

def get_data_components(x_mitre_datasource_id, ds_id):

    data_components = src.query([Filter("type", "=","x-mitre-data-component"), Filter("x_mitre_data_source_ref", "=", x_mitre_datasource_id)])

    for component in data_components:
       component_obj = {'ds_id':ds_id, 'type':'data_component','name':component['name'],'description':component['description']}
       exported_datasources.append(component_obj)

    return


def export_datasources():
   datasources = src.query([Filter("type", "=","x-mitre-data-source")])

   for datasource in datasources:
      print(datasource['external_references'])
      for i in range(len(datasource['external_references'])):
         if datasource['external_references'][i]['source_name'] == 'mitre-attack':
           id = datasource['external_references'][i]['external_id']

      datasource_obj = {'ds_id':id, 'name': datasource['name'], 'type': 'data_source', 'description': datasource['description'], 'platforms':",".join(datasource['x_mitre_platforms']), 'collection_layers':",".join(datasource['x_mitre_collection_layers']) }

      exported_datasources.append(datasource_obj)

      get_data_components(datasource['id'], id)

def csv_writer():
   csv_fields = ['ds_id','name','type','description','platforms','collection_layers']
   filename='attack_data_sources_'+datetime.now().strftime("%Y%m%d")+".csv"

   with open(filename, 'w') as csvfile:
       writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
       writer.writeheader()
       writer.writerows(exported_datasources)


def main():
   export_datasources()
   print("Writing to CSV....")
   csv_writer()

if __name__ == "__main__":
    sys.exit(main())
