# BRG
BRG-Work_daksh
# 📄 README: Suricata IDS Rule Mapping Pipeline (Google Colab)


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






## 🚀 Overview-BRGDemo3-Final
This repository/notebook provides an end-to-end pipeline for mapping **Suricata IDS rules** to **MITRE ATT&CK techniques** using:

- **OpenAI LLMs** (GPT-4 or GPT-3.5)
- **Pinecone** (for embedding-based fallback)
- **Hierarchical agent** approach for retrying invalid technique mappings
- **Batch processing** and partial saves to handle large rule sets efficiently

It’s designed to run in **Google Colab**, but can be adapted for other Python environments.

---

## 📊 Key Features

1. **Suricata IDS Rule Parsing:**
   - Reads a CSV file containing Suricata IDS rules (including `action`, `protocol`, `options`, etc.).
   - Extracts critical fields like `msg` and `classtype`.

2. **OpenAI GPT Integration:**
   - Sends each rule to GPT with a structured prompt to identify the correct MITRE ATT&CK technique.

3. **Hierarchical Agents & Retry Logic:**
   - **First Attempt:** The LLM tries to guess the best technique.
   - **Second Attempt (Fallback):** If invalid, we re-query the LLM with additional context (e.g., a technique list or correction note).
   - **Final Fallback (Embeddings):** If the LLM fails repeatedly, we rely on **Pinecone** for an embedding-based nearest match.

4. **Pinecone Embeddings:**
   - We store or retrieve MITRE technique embeddings (e.g., technique descriptions) in Pinecone.
   - If the LLM suggestions are invalid, Pinecone helps find a semantically similar technique.

5. **Faster Processing Techniques:**
   - **Batching**: Saves results in batches (e.g., every 2000 rules) to reduce I/O overhead.
   - **Partial Saves**: Checkpoints progress every 1000 rules (or a custom interval) to avoid data loss.
   - **Skipping Processed Rules**: Reads output JSON to skip rules already mapped.

---

## 🗂️ Folder Structure

├── suricata_extracted_rules_parsed.csv    # Input CSV with Suricata IDS rules
├── techniques.json                         # MITRE ATT&CK techniques reference
├── output_batches/                         # Folder where mapped results are saved
│   ├── mapped_results_1.json
│   ├── partial_1.json
│   ├── mapped_results_2.json
│   └── ...
├── notebook.ipynb                         # Colab notebook (main pipeline)
└── README.md                              # This README file
🔍 How the Pipeline Works
Load and Chunk Techniques (Optional):

The script reads techniques.json containing all MITRE techniques.
In older versions, it split them into chunks (e.g., 50 techniques per chunk) for LLM queries.
If you’re using a single large list, it includes all 240 techniques in one prompt.
Hierarchical Agent Workflow:

Agent 1 (LLM attempt #1): Takes a Suricata rule, tries to map it to a technique.
Agent 2 (LLM attempt #2): If Agent 1’s suggestion is invalid (not in techniques.json), it re-queries the LLM with a correction note or a full technique list.
Agent 3 (Pinecone): If both LLM attempts fail, we use an embedding-based similarity search to find the closest MITRE technique.
CSV Reading & Rule Skipping:

Reads the CSV via DictReader.
Skips any rule whose line number is below START_FROM_RULE.
Also checks output files in output_batches/ to skip rules already processed in previous runs.
LLM Query & Validation:

The code constructs a prompt detailing the Suricata IDS rule.
Sends it to the LLM (gpt-4 or gpt-3.5-turbo) with a temperature of 0.0 for deterministic responses.
Parses the JSON response to extract mitre_technique_id, mitre_technique_name, and confidence_score.
Fallback Using Pinecone:

If the LLM fails or the technique is invalid, Pinecone embeddings are used.
The script queries Pinecone for the best match given the technique name.
This ensures coverage if the LLM incorrectly responds with a non-existent technique.
Batch Processing and Partial Saves:

BATCH_SIZE: The number of rules processed before saving a final output JSON (e.g., 2000 rules per batch).
SAVE_INTERVAL: The number of processed rules before saving a partial checkpoint (e.g., 1000 rules).
Each batch or partial save is written to JSON, optionally downloaded within Colab.
💽 Example LLM Output
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
📝 Setup & Usage
Open the Notebook in Colab:
notebook.ipynb
Upload Files:
suricata_extracted_rules_parsed.csv (or your own CSV)
techniques.json
Install/Import Dependencies:
openai
pinecone (for embeddings)
Configure Keys:
Set OPENAI_API_KEY as an environment variable (or pass it in code).
Configure Pinecone credentials if needed.
Run the Notebook:
The pipeline will process the CSV rules, save batch results, and fallback to Pinecone if LLM fails.
🔄 Retry Mechanisms
Invalid Technique Handling:

If the technique is not found in techniques.json, the code triggers a second LLM attempt (with a hint or a full technique list).
If it fails again, Pinecone is queried for a nearest match.
Hierarchical Approach:

LLM → 2. LLM with Correction → 3. Pinecone.
Why?

Minimizes error rates by giving the LLM multiple attempts, then guaranteeing some fallback mapping if all else fails.
🌐 Pinecone Embedding DB
Role of Pinecone:
We store embeddings for each MITRE technique (e.g., technique name + description) in a Pinecone index.
When the LLM fails, we do an embedding similarity search in Pinecone.
Workflow:
retrieve_experiences(technique_name) returns the nearest matches based on embeddings.
If found, the top match is used as the fallback.
Configuration:
Make sure your Pinecone API key/index are set in the code.
⚡ Faster Processing Techniques
Partial Saves:
Every SAVE_INTERVAL rules, we store a partial JSON file. This ensures progress is never fully lost.
Batch Saves:
After BATCH_SIZE rules, we finalize a batch JSON (e.g., mapped_results_1.json).
Skipping Processed Rules:
The script checks previously generated JSON files to avoid repeating work.
Low Temperature & Structured Prompts:
Using temperature=0.0 for deterministic output.
Structured JSON prompts reduce ambiguity.
📌 Frequently Asked Questions
Q: Why does the rule ID start from 5251?
A: Because START_FROM_RULE = 5001, meaning the script skips the first 5000 lines of the CSV.

Q: How to process the entire CSV from the start?
A: Set START_FROM_RULE = 1.

Q: What if the LLM returns invalid JSON?
A: The rule is skipped or retried. We log a warning.

Q: How do I tune performance?
A: Adjust BATCH_SIZE, SAVE_INTERVAL, and potentially reduce the number of rules processed at once.

Q: Can I exclude Pinecone?
A: Yes. If you don’t want the embedding fallback, remove the Pinecone code and rely solely on LLM.
