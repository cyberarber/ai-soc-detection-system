from elasticsearch import Elasticsearch

es = Elasticsearch(['http://192.168.110.128:9200'])
if es.ping():
    print("✅ Connected to Elasticsearch!")
    info = es.info()
    print(f"Cluster: {info['cluster_name']}")
    print(f"Version: {info['version']['number']}")
else:
    print("❌ Connection failed")
