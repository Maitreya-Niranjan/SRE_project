# SRE_project

An interactive CLI tool to analyze malware behavior from **Procmon logs**, with integrated support for asking **cybersecurity-related questions** using Google's Generative AI (GenAI) API.

---

## Why I Built This

While analyzing large `Procmon` logfiles for malware behavior, I found it repetitive and tedious to manually trace:

- Dropped executables and suspicious files  
- Registry key modifications (`RegSetValue`, `RegCreateKey`)  
- File and process creation patterns like `CreateFile` or `ProcessStart`

On top of that, I frequently needed to search for explanations online — for example, understanding the implications of writing to `HKLM` or what operations point to a keylogger.

This project was built to solve both problems:

> A simple terminal-based tool that helps me **navigate Procmon logs quickly** and **ask contextual security questions**, without needing to leave the terminal.

---

## Features

- Load and parse `Procmon` CSV logs  
- View full or filtered datasets interactively  
- Extract:
  - Unique operations  
  - Unique paths  
  - Operations filtered by keywords or file types  
- Detect dropped files like `.exe`, `.dll`, `.dat`, etc.  
- Identify registry keys modified by malware  
- Ask natural-language questions like:
  - _“What does modifying HKLM imply?”_  
  - _“How do I detect a keylogger using Procmon?”_  
- Uses Google's GenAI API for accurate and detailed responses

> **Note:** Asking questions may take a few seconds depending on network and API latency, but responses are generally informative and accurate.

---

## Menu Options

Below are the options with the data present in the file: 
 1 - See the full data 
 2 - See all the unique operations in your data 
 3 - See the unique paths in the data 
 4 - See paths based on operation
 5 - See the paths based on a particular word
 6 - Find Registry Keys Modified
 7 - Find Dropped Files Based on File Creation + Extension Match
 8 - I have a doubt
 99 - To exit the program


---

## Future Work

Some potential future directions include:

- Using LLMs to **automatically classify suspicious behavior** from Procmon logs  
- Scoring processes based on known malware traits  
- Suggesting IOC (Indicator of Compromise) extractions  
- Integrating local models for faster offline inference  
- Exporting summaries in report-ready formats (Markdown, PDF, HTML)
