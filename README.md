# DNS Tunnel Guard

## Intro
DNS Tunnel Guard is a DNS tunneling detection and mitigation system meant to attach to any Linux DNS resolver. It listens to traffic leaving from and destined to the resolver program, analyzes the query with various detection methodologies,
and blocks the malicious domain and source IP address if the query is found to likely to be tunneling. 

## Methodologies
Current methodologies include rule based entropy analysis and traffic analysis. 

