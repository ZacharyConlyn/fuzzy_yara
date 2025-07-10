---

# fuzzy_yara

**Binary Ninja plugin to generate more flexible Yara rules**

## Overview

`fuzzy_yara` is a Binary Ninja plugin that automatically generates flexible Yara rules from functions or ranges in your x86 or AMD64 binary. It analyzes instructions, intelligently masks offsets and addresses with wildcards, and produces Yara rules that are robust to recompilation--even across operating systems--helping you detect behavior more robustly between malware variants.

## Features

- Generates Yara rules for selected functions or address ranges.
- Allows configuration for minimum byte count and non-wildcard byte count per rule.
- Sidebar widget for viewing and saving generated rules.
- Wildcarding of immediate and memory operands for flexibility.

## Installation

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
    - Open the "Fuzzy Yara Rule Editor" from the sidebar to view generated rules. Actually I didn't/don't know how to properly use the Binja API, so you HAVE to open this panel at least once before using the analysis functions. Once you open it once, you can close it freely and it should still work.

3. **Generate Yara rules:**
    - **Right-click** on a function or select a range in Binary Ninja.
    - Choose:
      - `Generate Fuzzy Yara rule (function)` – for a whole function
      - `Generate Fuzzy Yara rule (range)` – for a selected address range

4. **View and Save Rules:**
    - Generated rules appear in the sidebar widget
    - You can modify them to your heart's content
    - Click **Save** to export the rules to a file

5. **Configuration:**
    - Go to Binary Ninja’s Settings and search for “Fuzzy Yara Rule Generator”.
    - Adjust:
      - Minimum rule bytes (`fuzzyyara.min_rule_bytes`)
      - Minimum non-wildcard bytes (`fuzzyyara.min_non_wildcard_bytes`)

## Shoutouts
The original idea for this plugin came from CMU-SEI's Pharos, specifically the `fn2yara` analysis: https://github.com/cmu-sei/pharos/tree/master/tools/fn2yara . CMU-SEI also gave me the time and office space to work on this, and some guidance along the way. Finally they taught me the true power of friendship and to always believe in myself.
