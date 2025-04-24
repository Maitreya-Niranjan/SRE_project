# SRE_project

An interactive CLI tool to help analyze malware-related behavior in **Procmon logs**, with a built-in feature to directly ask **LLM-powered cybersecurity questions** using the Google API.

---

## Why I Built This

While working with large `Procmon` logfiles during malware analysis, I found it exhausting to manually trace:
- Dropped files
- Registry key modifications
- Suspicious operations like `CreateFile`, `RegSetValue`, and more

Worse, I constantly had to **Google what certain terms meant** or ask around to clarify common behavior patterns — like what modifying `HKLM` actually implies.

That’s what inspired this project:
> A simple CLI that helps **parse Procmon logs** AND lets me ask questions like _“What operations suggest a keylogger?”_ right from the terminal.

---

## Features

-  Parse and explore `Procmon` CSV logs
-  See full data or filtered subsets
-  Extract unique operations or paths
-  Identify dropped `.exe`, `.dll`, `.dat`, and other files
-  Detect modified **registry keys**
-  Ask doubts in plain English — answered by a Google LLM
-  Uses the internet via Google API (no local model setup)

---

##  Menu Options

```text
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
