# Sancus
A python tool designed to find Intra-Update Sniping Vulnerabilities in smart contracts. Can be applied to any updatable system with security levels.

## Usage
Set the "jText" variable equal to your initial configuration file and the "iText" variable equal to the target contract configuration file.

## Configuration File Sample
{"contracts": [{"name": "A","children": [{"name": "B","connect_sec": 1},{"name": "C","connect_sec": 0}]},{"name": "B", "children": [{"name":"D", "connect_sec": 0}]},{ "name": "C"}, {"name":"D"}]}

##Credits
Lepiller, Julien, et al. "Analyzing Infrastructure as Code to Prevent Intra-update Sniping Vulnerabilities." TACAS (2). 2021.
