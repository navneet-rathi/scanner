from flask import Flask, Response
import csv

app = Flask(__name__)

@app.route('/metrics')
def metrics():
    data = "# HELP compliance_status Compliance status by host\n# TYPE compliance_status gauge\n"
    data += "# HELP cve_count Number of CVEs detected\n# TYPE cve_count gauge\n"
    
    try:
        with open('/var/ansible/compliance_results.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                hostname, version = row
                status = 1 if version.startswith("5.4") else 0
                data += f'compliance_status{{host="{hostname}",version="{version}"}} {status}\n'
        
        with open('/var/ansible/cve_results.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                hostname, cve_report = row
                cve_count = cve_report.count("CVE-")
                data += f'cve_count{{host="{hostname}"}} {cve_count}\n'
                
    except Exception as e:
        data += f'# Error reading data: {str(e)}\n'
        
    return Response(data, mimetype='text/plain')

app.run(host='0.0.0.0', port=9100)
