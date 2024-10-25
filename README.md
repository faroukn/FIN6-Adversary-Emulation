# FIN6 Adversary Emulation Project

This project emulates the tactics, techniques, and procedures (TTPs) of the FIN6 advanced persistent threat (APT) group. FIN6 is known for targeting payment card data in point-of-sale (POS) environments, leveraging techniques such as memory scraping, credential dumping, and exfiltration via DNS tunneling. This emulation focuses on phases 1 and 2 of the FIN6 attack.

Phase 1 Start by Phishing email which downloads a Word doc file after opening it. a PowerShell metasploit payload runs after the Discovery of Users, Computers, Groups, OU, and other parts of the domain after that, the attacker compresses and extracts all that data using SSH through that attacker doing Privilege Escalation using various methods.

Phase 2 :



## Overview

The primary goal of this emulation is to provide a realistic representation of FIN6 TTPs in a controlled environment for educational and research purposes. This project includes:
- An infected Word document simulating a phishing payload.
- The `adfind.exe` tool for Active Directory enumeration.
- A C++ memory scraper targeting sensitive card data.
- A custom C2 server receiving exfiltrated data via DNS tunneling.


## Phases Breakdown

### Phase 1

#### Initial Access

Spearphishing Attachment: T1566.001 , Command and Scripting Interpreter: PowerShell: T1059.001

FIN6 has targeted victims with e-mails containing malicious attachments Craft a malicious Word document with embedded macros that execute the Metasploit PowerShell payload upon opening.

[infectd_word_doc](Phase1/infected_word_doc.doc)

---

![infectd_word_doc](Phase1/Screenshots/1.png)




## Credits

- This emulation project is inspired by open-source intelligence on the FIN6 APT group.
- Tools and techniques align with the MITRE ATT&CK framework.

---
