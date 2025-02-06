# BRG
BRG-Work_daksh
# 📄 README: Suricata IDS Rule Mapping Pipeline (Google Colab)

## 🚀 Overview- data folder
# `/data` Folder Overview

This folder contains various data files used for **Suricata** rule analysis, **MITRE ATT&CK** mapping, and documentation. Below is a high-level summary of each file and subfolder:

---

## Top-Level Files

### `testData_all.json`
- A JSON dataset containing Suricata rules or rule mappings.

### `testData.rules`
- A Suricata `.rules` file containing detection signatures for network intrusion.

### `techniques.json`
- A JSON listing of MITRE ATT&CK techniques 
- Used by scripts to validate or map IDS rules to specific technique IDs.

### `MITRE_ATTACK_TECHNIQUES.csv`
- A CSV variant of MITRE ATT&CK techniques data for reference or analysis in spreadsheet tools.

### `MITRE_ATTACK_TECHNIQUES.json`
- A JSON counterpart of the MITRE ATT&CK techniques, often used programmatically.

### `suricata_extracted_rules_parsed.numbers`
- A macOS Numbers spreadsheet containing parsed Suricata rule data (similar to CSV but in Apple’s Numbers format).

### `testDataMapped.json`
- A JSON file representing Suricata rules mapped to MITRE ATT&CK techniques.

### `testDataMapped.csv`
- A CSV version of the above mapped results (for easier viewing or sharing).

### `extracted_rules.json`
- A JSON dataset with Suricata rules extracted from one or more sources (processed result of `.rules` files).

### `mapped_rules_to_mitre.json`
- A JSON file containing IDS rule data alongside mapped MITRE technique information(given by jonathan i think).

### `testDataMapped_with_confidence.json` / `testDataMapped_with_confidence.csv`
- JSON and CSV outputs that not only map rules to ATT&CK techniques but also include a "confidence" field from an LLM or another scoring mechanism.

### `test_suricata_rules.json`
- Another test JSON file with Suricata rules,  used for experimentation or demonstration scripts.

### `suricata_extracted_rules_random_sampled.csv`
- A randomly sampled subset of Suricata rules (from a larger dataset) for testing, debugging, or proof-of-concept analysis around 512 rules.

### `emerging.rules.tar.gz`
- A compressed archive of Suricata rules from the **Emerging Threats** feed. May be used for bulk analysis or rule expansion.

---

## Documentation Subfolder

### `/data/documentation/`

- **`GambitASM.docx`**  
  A Word document containing in-depth details of my work.

- **`SuricataLLMMappings.pptx`**  
  A PowerPoint slide deck detailing how Suricata rules are mapped to MITRE ATT&CK using LLMs (e.g., GPT).

- **`Rescind_24Jan.pptx`**  
  Another PowerPoint containing threat-hunting findings, updates, or project status reports amd methodology diagram.

---

## Summary

In essence, the `/data` folder hosts:

1. **Suricata rules** (both raw `.rules` files and processed `.json`/`.csv` files).
2. **MITRE ATT&CK references** (JSON, CSV) for technique mapping.
3. **Intermediate & Final Mappings** (various `.json` and `.csv` outputs) showing which rules map to which MITRE techniques.
4. **Documentation** in Office formats (Word, PowerPoint) for project context or presentations.

## 🚀 Overview- BRGDemo
# Suricata Rule Mapping to MITRE ATT&CK

This script provides an end-to-end workflow for mapping Suricata rule data to specific MITRE ATT&CK techniques using OpenAI GPT and a retry mechanism. It includes:

- **LLM Prompting**: Generates a structured prompt for each rule.
- **Validation & Retry**: Ensures each returned technique ID matches a provided MITRE technique list, otherwise re-queries the LLM.
- **JSON Input/Output**: Loads rules/techniques from JSON files and saves mapped output to JSON for easy integration.
- **Batch Processing**: Demonstrates how to process a subset of rules (customizable).

---

## Table of Contents

1. [Overview](#overview)  
2. [Key Features](#key-features)  
3. [Dependencies & Setup](#dependencies--setup)  
4. [Script Flow](#script-flow)  
   - [1) Loading Extracted Rules](#1-loading-extracted-rules)  
   - [2) Loading MITRE ATT&CK Techniques](#2-loading-mitre-attck-techniques)  
   - [3) Mapping Rules to MITRE ATT&CK](#3-mapping-rules-to-mitre-attck)  
5. [Usage Instructions](#usage-instructions)  
6. [Customization](#customization)  
7. [Example Output](#example-output)  
8. [License](#license)

---

## Overview

- **Purpose**: Automate the classification of Suricata rule messages into MITRE ATT&CK techniques.  
- **Core Approach**:  
  1. Prompt an LLM (OpenAI GPT) with rule info.  
  2. Enforce a valid MITRE technique.  
  3. Retry if the initial technique is invalid.

---

## Key Features

1. **OpenAI GPT Integration**  
   - Uses ChatGPT-like completions with a structured prompt.  
   - Custom system/user messages for cybersecurity context.

2. **Validation & Retry**  
   - Ensures the returned `mitre_technique_id` matches a known list.  
   - If invalid, re-queries with a stricter prompt.

3. **JSON-Based I/O**  
   - Loads Suricata rules from a JSON file.  
   - Saves final mappings in a clean JSON format.

4. **Logging & Timing**  
   - Tracks each rule’s ID, prints LLM responses, and measures API call durations.

5. **Partial Processing**  
   - By default, processes a limited number of rules (e.g., 10).  
   - Easily modified to handle larger batches.

---




## 🚀 Overview- BRGDemo2
# Suricata Rule Parsing & MITRE Mapping

This script provides a two-stage approach for working with Suricata rules:

1. **Parsing Rules**: Extracting rule information (such as `msg`, `classtype`, and `sid`) from a `.rules` file and saving it to JSON.
2. **Mapping to MITRE ATT&CK**: Taking an existing CSV of Suricata rules (with relevant fields) and using the OpenAI API to map each rule to three MITRE ATT&CK techniques (with confidence scores).

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Usage](#usage)
   - [Step 1: Parsing Suricata Rules File](#step-1-parsing-suricata-rules-file)
   - [Step 2: Mapping CSV Data to MITRE Techniques](#step-2-mapping-csv-data-to-mitre-techniques)
5. [Key Components](#key-components)
   - [Regex Patterns](#regex-patterns)
   - [LLM Queries & Caching](#llm-queries--caching)
6. [Command-Line Execution](#command-line-execution)
7. [Customization](#customization)
8. [License](#license)

---

## Overview

This script (`parse_rules_file` + `process_csv_and_map_to_mitre`) handles two major functionalities:

1. **`parse_rules_file(...)`**  
   Reads a Suricata `.rules` file, extracts important fields (`msg`, `classtype`, `sid`), and outputs JSON.

2. **`process_csv_and_map_to_mitre(...)`**  
   Reads Suricata rule data from a CSV (where each row includes fields like `file_name`, `action`, `protocol`, etc.), then uses the OpenAI API to map each rule to MITRE ATT&CK techniques with confidence scores. The final mappings are saved to a JSON output file.

---

## Prerequisites

1. **Python 3.7+**  
2. **OpenAI API Key**  
   - Stored in an environment variable named `OPENAI_API_KEY`.
3. **Suricata `.rules` file(s)** or existing CSV output from prior steps.

---





## 🚀 Overview- Suricata Rule Enhancer

This Python script (`suricata_rule_enhancer.py`) streamlines the extraction and sampling of Suricata rules from `.rules` files, allowing you to parse them into a structured format (CSV) and optionally take random samples for further analysis or curation.

## Table of Contents

1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Usage](#usage)
    - [Extracting and Parsing Rules](#extracting-and-parsing-rules)
    - [Random Sampling of CSV Data](#random-sampling-of-csv-data)
5. [Command-Line Execution](#command-line-execution)
6. [How It Works](#how-it-works)
    - [Regex Parsing](#regex-parsing)
    - [CSV Output Format](#csv-output-format)
7. [Customization](#customization)
8. [Contributing](#contributing)
9. [License](#license)

---

## Features

- **Rule Extraction**: Processes all `.rules` files in a specified directory, ignoring comment lines and automatically filtering out irrelevant lines (e.g., `$Id:`, `version`, `generated`).
- **Regex-Based Parsing**: Parses each Suricata rule’s structure into columns (action, protocol, source/destination addresses and ports, and options).
- **CSV Output**: Writes parsed rule data to a CSV file for easy consumption and analysis.
- **Random Sampling**: Supports random sampling of the extracted rules for cases where you have a large dataset but only want to inspect or test with a subset.

---

## Prerequisites

1. **Python 3.7+** installed.
2. A **Suricata rules folder** containing `.rules` files to parse.

---


## 🚀 Overview-Pinecone
# Pinecone Vector Database Integration

This repository/notebook (`pincone.ipynb`) demonstrates how to set up and use Pinecone as a vector database to store, index, and retrieve text documents via embeddings. This setup is especially useful for powering advanced search or chatbots using semantic search capabilities.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Environment Variables](#environment-variables)
5. [Usage](#usage)
   - [Initializing `customVectorDB`](#initializing-customvectordb)
   - [Storing Data](#storing-data)
   - [Retrieving Data](#retrieving-data)
   - [Deleting the Index](#deleting-the-index)
6. [Experience Manager](#experience-manager)
7. [Example Workflow](#example-workflow)
8. [Notes & Considerations](#notes--considerations)

---

## Overview

This notebook uses the following main components to create and manage a Pinecone-backed vector database:

- **[Pinecone](https://www.pinecone.io/)**: A fully managed, serverless vector database.
- **[LangChain Community Fork](https://github.com/hwchase17/langchain)**: A suite of tools for building AI applications, including:
  - Document loaders
  - Embedding models
  - Vector store integrations
- **OpenAI's text embeddings**: Specifically `text-embedding-ada-002` (dimension=1536), used for generating vector representations of text.

### `customVectorDB`
A custom class that handles:
- Pinecone initialization.
- Creation and management of the Pinecone index.
- Storing text/files and performing similarity searches.

### `ExperienceManager`
A higher-level wrapper that uses `customVectorDB` to store and retrieve documents (referred to as "experiences").

---

## Prerequisites

Before running this notebook, ensure you have:

1. **Python 3.7+**
2. **A Pinecone account** (with an API key).
3. **OpenAI API key** (for generating text embeddings).

---

## Installation

In the first cells of the notebook, the following packages are installed:

!pip install pinecone-client langchain_community






# 🚀 Overview-BRGDemo3-Final

This repository/notebook provides an **end-to-end pipeline** for mapping **Suricata IDS rules** to **MITRE ATT&CK techniques** using:

- **OpenAI LLMs** (GPT-4 or GPT-3.5)
- **Pinecone** (for embedding-based fallback)
- A **hierarchical agent** approach for retrying invalid technique mappings
- **Batch processing** and partial saves to handle large rule sets efficiently

It’s designed to run primarily in **Google Colab**, but it can be adapted for other Python environments.

---

## Table of Contents

1. [Key Features](#key-features)  
2. [Folder Structure](#folder-structure)  
3. [Pipeline Workflow](#pipeline-workflow)  
   - [Load and Chunk Techniques (Optional)](#load-and-chunk-techniques-optional)  
   - [Hierarchical Agent Workflow](#hierarchical-agent-workflow)  
   - [CSV Reading & Rule Skipping](#csv-reading--rule-skipping)  
   - [LLM Query & Validation](#llm-query--validation)  
   - [Fallback Using Pinecone](#fallback-using-pinecone)  
   - [Batch Processing & Partial Saves](#batch-processing--partial-saves)  
4. [Example LLM Output](#example-llm-output)  
5. [Setup & Usage](#setup--usage)  
6. [Retry Mechanisms](#retry-mechanisms)  
7. [🌐 Pinecone Embedding DB](#-pinecone-embedding-db)  
8. [⚡ Faster Processing Techniques](#-faster-processing-techniques)  
9. [📌 Frequently Asked Questions](#-frequently-asked-questions)  

---

## Key Features

1. **Suricata IDS Rule Parsing**  
   - Reads from a CSV file containing Suricata IDS rules (fields like `action`, `protocol`, `options`, etc.).  
   - Extracts critical fields such as `msg` and `classtype`.

2. **OpenAI GPT Integration**  
   - Sends each rule to GPT (4 or 3.5) with a structured prompt to identify the correct MITRE ATT&CK technique.

3. **Hierarchical Agents & Retry Logic**  
   1. **First Attempt**: The LLM attempts to find the best technique.  
   2. **Second Attempt**: If invalid, re-queries the LLM with additional context (e.g., technique list or a correction note).  
   3. **Final Fallback (Pinecone)**: If LLM fails repeatedly, an embedding-based nearest match is used.

4. **Pinecone Embeddings**  
   - Stores or retrieves MITRE technique embeddings (e.g., technique descriptions) in Pinecone.  
   - If the LLM suggestions are invalid, Pinecone helps find the closest technique via similarity search.

5. **Faster Processing**  
   - **Batching**: Saves results in batches (e.g., every 2000 rules) to reduce I/O overhead.  
   - **Partial Saves**: Checkpoints progress every 1000 rules (configurable) to prevent data loss.  
   - **Skipping Processed Rules**: Reads the existing JSON to skip rules that have already been mapped.

---

## Folder Structure

```plaintext
├── suricata_extracted_rules_parsed.csv    # Input CSV with Suricata IDS rules
├── techniques.json                         # MITRE ATT&CK techniques reference
├── output_batches/                         # Folder where mapped results are saved
│   ├── mapped_results_1.json
│   ├── partial_1.json
│   ├── mapped_results_2.json
│   └── ...
├── notebook.ipynb                         # Colab notebook (main pipeline)
└── README.md                              # This README file
Pipeline Workflow
Below is a high-level overview of the pipeline steps:

Load and Chunk Techniques (Optional)
The script reads techniques.json containing MITRE technique data.
In older versions, it split them into chunks (e.g., 50 techniques per chunk) for smaller LLM prompts.
Alternatively, you can load all 240+ techniques at once (a single large list).
Hierarchical Agent Workflow
Agent 1 (LLM attempt #1): Takes a Suricata rule, attempts to map it to a valid MITRE technique.
Agent 2 (LLM attempt #2): If Agent 1’s suggestion is invalid (not in techniques.json), re-queries the LLM with additional instructions (like a correction note or full technique list).
Agent 3 (Pinecone): If both attempts fail, uses an embedding-based similarity search in Pinecone to pick the best match.
CSV Reading & Rule Skipping
The code reads the CSV (e.g., suricata_extracted_rules_parsed.csv) with a Python DictReader.
Skips rules below a specified line number START_FROM_RULE.
Also checks output_batches/ to skip rules that have already been processed in prior runs.
LLM Query & Validation
The script constructs a prompt describing the Suricata IDS rule.
Sends it to the LLM (gpt-4 or gpt-3.5-turbo) with temperature=0.0 for deterministic output.
Parses the JSON response to extract fields like mitre_technique_id, mitre_technique_name, and confidence_score.
Fallback Using Pinecone
If the LLM fails or the suggested technique is invalid, it queries Pinecone’s index for the closest match.
This ensures coverage if the LLM incorrectly responds with a non-existent technique.
Batch Processing & Partial Saves
BATCH_SIZE: The number of rules to process before a final output JSON is saved (e.g., 2,000).
SAVE_INTERVAL: The number of rules before a partial checkpoint save (e.g., 1,000).
Each batch or partial save is written to JSON and optionally downloaded (in Colab).
Example LLM Output
json
Copy
Edit
{
  "suri_rule_id": "emerging-malware.rules_5251",
  "file_name": "emerging-malware.rules",
  "action": "alert",
  "protocol": "tcp",
  "src_addr": "any",
  "src_port": "any",
  "dst_addr": "any",
  "dst_port": "80",
  "options": "msg:\"Potential Malware\"; classtype:trojan-activity;",
  "suri_rule_classtype": "trojan-activity",
  "suri_rule_msg": "Potential Malware",
  "mitre_technique_id": "T1059",
  "mitre_technique_name": "Command and Scripting Interpreter",
  "confidence_score": "0.90"
}
Setup & Usage
Open the Notebook in Colab

See notebook.ipynb.
Upload Your Files

suricata_extracted_rules_parsed.csv (or your own CSV).
techniques.json (MITRE ATT&CK techniques).
Install/Import Dependencies

openai
pinecone
Configure API Keys

Set OPENAI_API_KEY as an environment variable (or inline in the code).
Configure Pinecone credentials if using the fallback embeddings approach.
Run the Notebook

The pipeline will process the CSV rules, save batch results, and fallback to Pinecone for technique matching as needed.
Retry Mechanisms
Invalid Technique Handling
If the technique from the LLM is not found in techniques.json, the script triggers a second LLM attempt with additional context.
Failing that, Pinecone is queried for a nearest match.
Hierarchical Approach
LLM (initial)
LLM (with correction)
Pinecone
This approach lowers error rates by giving the LLM multiple attempts before guaranteeing a fallback match via embeddings.

🌐 Pinecone Embedding DB
Role of Pinecone
Stores embeddings for each MITRE technique (e.g., name + description) in a Pinecone index.
If the LLM fails, we use embedding-based similarity search to find the closest technique.
Configuration
Set your Pinecone API key and index name in the code or environment variables.
Use retrieve_experiences(technique_name) (or equivalent function) to fetch the nearest matches.
⚡ Faster Processing Techniques
Partial Saves: Saves progress every SAVE_INTERVAL rules to avoid data loss.
Batch Saves: After BATCH_SIZE rules, creates a final batch JSON.
Skipping Processed Rules: Checks previously generated JSON files to avoid re-processing.
Low Temperature & Structured Prompts: Ensures deterministic LLM output and reduces confusion.
📌 Frequently Asked Questions
Q: Why does the rule ID start from 5251?
A: Because START_FROM_RULE = 5001, meaning the script skips the first 5,000 lines of the CSV.

Q: How do I process the entire CSV from the beginning?
A: Set START_FROM_RULE = 1.

Q: What if the LLM returns invalid JSON?
A: The rule is skipped or retried, and a warning is logged.

Q: How do I tune performance?
A: Adjust BATCH_SIZE, SAVE_INTERVAL, and reduce the number of rules processed at once.

Q: Can I exclude Pinecone?
A: Yes. If you don’t want the embedding fallback, remove the Pinecone logic and rely solely on the LLM.

