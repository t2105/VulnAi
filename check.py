import json, socket, sys
host=sys.argv[1]
for port in (21,22,23,80,139,445,3306,3632):
    try:
        with socket.create_connection((host,port),timeout=1): status='open'
    except OSError: status='closed or filtered'
    print(json.dumps({'target':host,'port':port,'status':status}),flush=True)
