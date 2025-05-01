import json
from collections import Counter

def extract_and_count_domains(data):
    domain_counter = Counter()

    for packet in data:
        if 'dns' in packet:
            for dns_record in packet['dns']:
                if 'queries' in dns_record:
                    for query in dns_record['queries']:
                        domain_counter[query['name']] += 1
        if 'tls' in packet and 'handshake' in packet['tls']:
            if 'extensions' in packet['tls']['handshake']:
                for ext in packet['tls']['handshake']['extensions']:
                    if ext['type'] == 'server_name':
                        domain_counter[ext['server_name']] += 1

    return domain_counter

def main():
    with open("filtered_data.json", "r") as file:
        data = json.load(file)

    domain_counts = extract_and_count_domains(data)

    print("Domain Contact Counts:")
    for domain, count in domain_counts.most_common():
        print(f"{domain}: {count}")

if __name__ == "__main__":
    main()
