import os
import subprocess

password = "1234"
user_input = input("Enter a file to delete: ")
os.system(f"rm -rf {user_input}")  
subprocess.call("ls -l " + user_input, shell=True)  
