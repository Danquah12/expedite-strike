from app.nl_interface import api_nl_query
import json

query = input("Enter query: ")
result = api_nl_query(query)
print(json.dumps(result, indent=2))
