Certainly! Here’s a README.md draft for your **fuzzy_yara** Binary Ninja plugin:

---

# fuzzy_yara

**Binary Ninja plugin to generate more flexible Yara rules**

## Overview

`fuzzy_yara` is a Binary Ninja plugin that automatically generates flexible Yara rules from functions or ranges in your binary analysis. It analyzes instructions, intelligently masks bytes (wildcards), and produces Yara rules that are robust to small changes, helping you detect malware or similar binaries even if they have minor modifications.

## Features

- Generates Yara rules for selected functions or address ranges.
- Allows configuration for minimum byte count and non-wildcard byte count per rule.
- Sidebar widget for viewing and saving generated rules.
- Wildcarding of immediate and memory operands for flexibility.

## Installation

### Requirements

- [Binary Ninja](https://binary.ninja/)
- Python 3
- [capstone](https://www.capstone-engine.org/) (Python bindings)
- [PySide6](https://pypi.org/project/PySide6/)

### Steps

1. **Clone the repository:**

   ```shell
   git clone https://github.com/ZacharyConlyn/fuzzy_yara.git
   ```

2. **Install dependencies:**

   You may need to install Capstone if you haven't already. Binja gives you an easy way to do that: `View -> Command Palette -> Install Python3 Module` and enter `capstone` 


4. **Copy `fuzzy_yara.py` to your Binary Ninja plugins folder:**

   - On most systems, this is `~/.binaryninja/plugins/`

5. **Restart Binary Ninja.**

## Usage

1. **Open a binary in Binary Ninja.**

2. **Sidebar Widget:**
    - Open the "Fuzzy Yara Rule Editor" from the sidebar to view generated rules. Actually I didn't/don't know how to properly use the Binja API so you HAVE to open this panel at least once (you can close again) before using the analysis functions.

3. **Generate Yara rules:**
    - **Right-click** on a function or select a range in Binary Ninja.
    - Choose:
      - `Generate Fuzzy Yara rule (function)` – for a whole function
      - `Generate Fuzzy Yara rule (range)` – for a selected address range

4. **View and Save Rules:**
    - Generated rules appear in the sidebar widget.
    - You can modify them to your heart's content
    - Click **Save** to export the rules to a file.

5. **Configuration:**
    - Go to Binary Ninja’s Settings and search for “Fuzzy Yara Rule Generator”.
    - Adjust:
      - Minimum rule bytes (`fuzzyyara.min_rule_bytes`)
      - Minimum non-wildcard bytes (`fuzzyyara.min_non_wildcard_bytes`)

