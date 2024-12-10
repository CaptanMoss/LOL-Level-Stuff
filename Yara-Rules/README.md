# YARA Rules for Detecting MeltingClaw and ShadyHammock Malware

This repository contains YARA rules designed to detect three specific malware families: **MeltingClaw**, **ShadyHammock**, and **QuickHeal**. The rules are based on unique file hashes and behavior patterns identified during analysis. The repository includes the YARA rules themselves and the corresponding output screenshots from testing the rules.

## Contents
- `yara-rules/`: Contains the YARA rules for malware detection.
- `outputs/`: Screenshots showing the detection results for the rules.

## Detected Malware
### MeltingClaw
The following file hashes are associated with the MeltingClaw malware family:
- `45adf6f32f9b3c398ee27f02427a55bb3df74687e378edcb7e23caf6a6f7bf2a`
- `B9677c50b20a1ed951962edcb593cce5f1ed9c742bc7bff827a6fc420202b045`

### ShadyHammock
The following file hashes are associated with the ShadyHammock malware family:
- `ce8b46370fd72d7684ad6ade16f868ac19f03b85e35317025511d6eeee288c64`
- `9f635fa106dbe7181b4162266379703b3fdf53408e5b8faa6aeee08f1965d3a2`
- `1fa96e7f3c26743295a6af7917837c98c1d6ac0da30a804fed820daace6f90b0`

### QuickHeal
The following file hash is associated with the QuickHeal malware family:
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
   yara MeltingClaw.yara <target_file>
   yara ShadyHammock.yara <target_file>
   yara QuickHeal.yara <target_file>


## Screenshots
Screenshots demonstrating the detection outputs are included in the outputs/ directory.


## Contributing
Feel free to open issues or pull requests if you find errors in the rules or want to contribute enhancements.

## Disclaimer
These YARA rules are provided for educational and research purposes only. Use them responsibly and ensure compliance with applicable laws and regulations.