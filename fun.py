#.\sre_project\Scripts\activate
import pandas as pd
import os
from huggingface_hub import InferenceClient
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from google import genai
import json

API_KEY = ""  # Add your own key or else contact me at maitreya.niranjan@tamu.edu



class FileLoader:
    def __init__(self, filename):
        self.filename = filename
        self.data = None

    def load(self):
        try:
            self.data = pd.read_csv(self.filename)
            print(f"Loaded {len(self.data)} rows from '{self.filename}'")
            c_name = self.data.columns
            print("The differnt columns present are:",list(c_name))
            print(self.data.shape)
            return True
        
        except FileNotFoundError:
            print("File not found.")
            return False
        
        except pd.errors.ParserError:
            print("Could not parse the CSV. Check file format.")
            return False
        
        
class UniqueOperation:
    def __init__(self, data, op = None):
        self.data = data
        self.op_chosen = op
        
    def run(self):
        operations = self.data["Operation"].unique()
        operations.sort()
        for i in operations:
            print(i)
            
    def choose(self):
        if not self.op_chosen:
            print("No operation type specified.")
            return []
        rows = self.data[self.data["Operation"]==self.op_chosen]
        print(rows)


class UniquePath:
    def __init__(self, data, file = None):
        self.data = data
        self.file = file
        
    def run(self):
        paths = self.data["Path"].unique()
        for i in paths:
            print(i)
            
    def choose(self):
        if not self.file:
            print("Nothing specified.")
            return []
        filtered = self.data[self.data["Path"].str.contains(self.file, case=False, na=False)]
        matching_paths = filtered["Path"].unique()
        print(f"\n Paths containing '{self.file}':")
        for path in matching_paths:
            print(path)
        return matching_paths
    
    def filetype(self):
        if not self.file:
            print("No file type specified.")
            return []
        filtered = self.data[self.data["Path"].str.lower().str.endswith(f".{self.file.lower()}", na=False)]
        filenames = filtered["Path"].apply(lambda x: os.path.basename(x)).unique()
        print(f"\n Unique '.{self.file}' files:")
        filenames = sorted(filenames)
        for f in filenames:
            print(f)
        return filenames


class ModifiedRegistryViewer:
    def __init__(self, df):
        self.df = df

    def run(self):
        print("\nRegistry Keys Modified by the Malware:\n")
        operations = ["RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey"]
        filtered = self.df[self.df["Operation"].isin(operations)]
        if filtered.empty:
            print("No registry modification operations found.")
            return
        registry_dict = {}
        for op in operations:
            op_paths = filtered[filtered["Operation"] == op]["Path"].unique()
            registry_dict[op] = sorted(op_paths)
        for op, paths in registry_dict.items():
            print(f"\n{op} ({len(paths)} entries):")
            for path in paths:
                print(f"  - {path}")

        print(f"\nTotal operations found: {sum(len(v) for v in registry_dict.values())}")

class DroppedFileFinder:
    def __init__(self, df, extensions=["exe", "dll", "dat", "log"]):
        self.df = df
        self.extensions = extensions

    def run(self):
        print("\nSearching for dropped files (CreateFile with target extensions)...")

        filtered = self.df[self.df["Operation"] == "CreateFile"]

        result_paths = []
        for ext in self.extensions:
            match = filtered[filtered["Path"].str.lower().str.endswith(f".{ext}", na=False)]
            result_paths.extend(match["Path"].tolist())

        result_paths = sorted(set(result_paths))

        if not result_paths:
            print("No dropped files found.")
        else:
            print(f"\nFound {len(result_paths)} dropped file(s):")
            for path in result_paths:
                print(f"  - {path}")





class Doubt:
    def __init__(self, prompt=None):
        self.prompt = prompt

    def run(self):
        payload = {
        "query": self.prompt,
        "api_key": API_KEY
        }
        client = genai.Client(api_key=API_KEY)
        prompt = ("Answer the following question like a Malware analysis expert. Answer to the point, and keep it to 5 sentences."+ " Question:"+self.prompt)
        response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        if response:
            print(response.text)
        else:
            return json.jsonify({"error": "Failed to get response from Gemini API"}), 500

class ProcmonShell:
    def __init__(self, data):
        self.data = data

    def run(self):
        while True:
            print("\nBelow are the options with the data present in the file:\n1 - See the full data\n2 - See all the unique operations in your data\n3 - See the unique paths in the data\n4 - See paths based on operation\n5 - See the paths based on a particular word\n6 - Find Registry Keys Modified\n7 - Find Dropped Files Based on File Creation + Extension Match\n8 - I have a doubt\n99 - To exit the program")
            option = int(input("Enter your option: "))

            if option == 1:
                print(self.data)
                            
            elif option == 2:
                UniqueOperation(self.data).run()
            
            elif option == 3:
                UniquePath(self.data).run()
                
                
            elif option == 4:
                op = input("Enter the operation:")
                UniqueOperation(self.data, op).choose()
            
            elif option == 5:
                option = input("are you searching for a particular file(y/n)>:")
                if option == "n":
                    op = input("Enter the word you want to search for in path:")
                    UniquePath(self.data, op).choose()
                elif option =="y":
                    op = input("Enter the type of file you want to search for:")
                    UniquePath(self.data, op).filetype()
                
            elif option == 6:
                ModifiedRegistryViewer(self.data).run()
                
            elif option == 7:
                DroppedFileFinder(self.data).run()
            
            elif option == 8:
                a =input("Enter your doubt: ")
                Doubt(prompt = a).run()

            else:
                break




        
if __name__ == "__main__":
    #filename = input("Enter the name of the CSV file: ")
    filename = "Logfile.csv"
    loader = FileLoader(filename)
    if loader.load():
        shell = ProcmonShell(loader.data)
        shell.run()

