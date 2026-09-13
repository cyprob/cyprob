# CLI Integrations

Learn how to integrate Vulntor CLI with automation tools, CI/CD pipelines, and scripting environments.

## Cron Scheduling

Schedule periodic scans using cron:

```bash
# /etc/cron.d/vulntor-scan
0 2 * * * vulntor-user /usr/local/bin/vulntor scan --targets /etc/vulntor/targets.txt --quiet
```

## CI/CD Pipeline

### GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: vulntor/vulntor:latest
  script:
    - vulntor scan --targets $CI_ENVIRONMENT_URL --output report.json
  artifacts:
    reports:
      vulntor: report.json
```

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run Vulntor scan
        uses: vulntor/vulntor-action@v1
        with:
          targets: ${{ secrets.SCAN_TARGETS }}
          profile: standard
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'vulntor scan --targets ${TARGET_NETWORK} --output report.json'
                archiveArtifacts artifacts: 'report.json'
            }
        }
    }
}
```

## Ansible Playbook

```yaml
- name: Run Vulntor scan
  command: >
    vulntor scan
    --targets {{ target_network }}
    --profile standard
    --output /tmp/scan-results.json
  register: scan_result

- name: Parse scan results
  set_fact:
    vulnerabilities: "{{ lookup('file', '/tmp/scan-results.json') | from_json }}"
```

## Python Script

```python
import subprocess
import json

result = subprocess.run(
    ['vulntor', 'scan', '--targets', '192.168.1.100', '--output', 'json'],
    capture_output=True,
    text=True
)

if result.returncode == 0:
    scan_data = json.loads(result.stdout)
    print(f"Found {len(scan_data['results'])} hosts")
else:
    print(f"Scan failed: {result.stderr}")
```

## Bash Script

```bash
#!/bin/bash

# Run scan and capture output
vulntor scan --targets 192.168.1.0/24 --output json > scan.json

# Check exit code
if [ $? -eq 0 ]; then
    # Parse results with jq
    vulnerabilities=$(jq '[.results[].vulnerabilities[]] | length' scan.json)
    echo "Found $vulnerabilities vulnerabilities"

    # Send to webhook
    curl -X POST https://alerts.company.com/webhook \
         -H "Content-Type: application/json" \
         -d @scan.json
else
    echo "Scan failed"
    exit 1
fi
```

## Terraform

```hcl
resource "null_resource" "security_scan" {
  provisioner "local-exec" {
    command = "vulntor scan --targets ${aws_instance.web.public_ip} --output report.json"
  }

  depends_on = [aws_instance.web]
}
```

## Docker Integration

```dockerfile
FROM vulntor/vulntor:latest

COPY targets.txt /app/targets.txt
WORKDIR /app

ENTRYPOINT ["vulntor", "scan"]
CMD ["--targets", "targets.txt", "--output", "results.json"]
```

Run as container:

```bash
docker run -v $(pwd)/results:/app/results vulntor-scanner
```

## Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vulntor-scan
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: vulntor
            image: vulntor/vulntor:latest
            args:
            - scan
            - --targets
            - "10.0.0.0/16"
            - --output
            - /results/scan.json
            volumeMounts:
            - name: results
              mountPath: /results
          volumes:
          - name: results
            persistentVolumeClaim:
              claimName: vulntor-results
          restartPolicy: OnFailure
```
