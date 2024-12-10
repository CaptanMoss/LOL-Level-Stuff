# YARA Rule for QuickHeal Malware Detection

This repository contains a YARA rule specifically designed to detect the **QuickHeal malware variant**, identified through its unique hash. The rule aims to support security analysts and SOC teams in detecting and mitigating this threat effectively.

## Detected Malware
### QuickHeal
The following file hash is associated with the QuickHeal malware sample analyzed:
- `1906e7d5a745a364c91f5e230e16e1566721ace1183a57e8d25ff437664c7d02`

## How to Use
1. Clone this repository:
   ```bash
   git clone https://github.com/CaptanMoss/LOL-Level-Stuff.git
2. Navigate to the rules/ directory:
   ```bash
   cd LOL-Level-Stuff/yara-rules/
3. Run the YARA rules against your target files:
   ```bash
    yara QuickHeal.yara <target_file>

## Testing the Rule
The repository includes:

- The YARA rule file: QuickHeal.yara
- Screenshots showing the detection output in the outputs/ directory for validation.
    
## About QuickHeal Malware
QuickHeal is a malware variant identified as part of advanced threat campaigns. This rule focuses on detecting the sample with the hash mentioned above, enabling security teams to quickly identify and analyze this threat.

## Disclaimer
This YARA rule is provided for educational and research purposes only. Ensure compliance with applicable laws and organizational policies when using this rule.