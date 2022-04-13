from stix2 import Filter, TAXIICollectionSource, MemorySource
from taxii2client.v20 import Collection # only specify v20 if your installed version is >= 2.0.0

import argparse
import csv
import io
import tqdm

def build_taxii_source(collection_name):
    collections = {
        "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
        "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b",
        "ics-attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
    }

    collection_url = "https://cti-taxii.mitre.org/stix/collections/" + collections[collection_name] + "/"
    collection = Collection(collection_url)
    livesrc = TAXIICollectionSource(collection)

    return MemorySource(stix_data=livesrc.query())

def get_technique(src, source_name, object_id):
    filters = [
        Filter("type", "=", "attack-pattern"),
        Filter("external_references.source_name", "=", source_name),
        Filter("id", "=", object_id)
    ]

    results = src.query(filters)

    return results

def getAllRevoked(thesrc):
    return thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', "revoked-by")
    ])

def grab_external_id(stix_object, source_name):
    for s in range(len(stix_object)):
        for external_reference in stix_object[s]['external_references']:
            if external_reference['source_name'] == source_name:
                attack_id = external_reference['external_id']
    return attack_id

def arg_parse():
    """Function to handle script arguments."""
    parser = argparse.ArgumentParser(description="Fetches the current ATT&CK content expressed as STIX2 and creates spreadsheet mapping Techniques with Mitigations, Groups or Software.")
    parser.add_argument("-d", "--domain", type=str, required=True, choices=["enterprise_attack", "mobile_attack"], help="Which ATT&CK domain to use (Enterprise, Mobile).")
    parser.add_argument("-s", "--save", type=str, required=False, help="Save the CSV file with a different filename.")
    return parser

def do_maps(ds, source_name, filename):
    all_revoked_patterns = getAllRevoked(ds)
    writeable_results = []

    for revoked_pattern in tqdm.tqdm(all_revoked_patterns, desc="parsing data for revoked techniques"):
        revoked_technique = get_technique(ds, source_name, revoked_pattern.source_ref)
        new_technique = get_technique(ds, source_name, revoked_pattern.target_ref)
        if revoked_technique:
            old_id = grab_external_id(revoked_technique, source_name)
            new_id = grab_external_id(new_technique, source_name)
            old_name = revoked_technique[0]['name']
            technique_obj = {'revoked_id':old_id,'revoked_name':old_name,'revoked_date':revoked_pattern.created,'new_id':new_id}
            writeable_results.append(technique_obj)

    return writeable_results

def csv_writer(results_obj, filename):
    csv_fields = ['revoked_id','revoked_name','revoked_date','new_id']
    with open(filename, 'w') as csvfile:
       writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
       writer.writeheader()
       writer.writerows(results_obj)

def main(args):
    data_source = build_taxii_source('enterprise_attack')
    source_map = {
        "enterprise_attack": "mitre-attack",
        "mobile_attack": "mitre-mobile-attack",
    }
    source_name = source_map[args.domain]
    filename = args.save or "revoked.csv"
    revoked_techniques = do_maps(data_source, source_name, filename)
    csv_writer(revoked_techniques, filename)

if __name__ == "__main__":
    parser = arg_parse()
    args = parser.parse_args()
    main(args)
