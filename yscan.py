import os
import sys
import argparse
import yara
import re
import time
import json
import logging

VERSION = "0.1.5"
# Set up logging
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# command line options:
# folder to scan, YARA rule file to use, file where SBOM report will be written
def handle_arguments():
    # Define the command-line arguments
    parser = argparse.ArgumentParser(description="Scan a folder for files that match a YARA pattern.")
    parser.add_argument("folder", help="The folder to scan.")
    parser.add_argument("rule_file", help="The filename for the YARA pattern.")
    parser.add_argument("result_file", help="The filename where the SBOM will be written.")
    parser.add_argument("--symlink", action="store_true", help="Will scan files / folders that are symlinks.")
    parser.add_argument("--verbose", action="store_true", help="Display scan results while scanning.")
    parser.add_argument("--nopath", action="store_true", help="Remove folder given from path.")
    parser.add_argument("--version", action="version", version=VERSION, help="Display the program version.")
    args = parser.parse_args()

    # check if program should scan symlinks
    if args.symlink:
        logging.info("Scanning for symlinks ENABLED.")
    else:
        logging.info("Symlinks scanning DISABLED.")

    # Check if the user requested help
    if args.rule_file == "--help":
        parser.print_help()
        sys.exit(0)

    return args


# extract the product and version from the given string
def extractVersion(product):
    regex = r'(\D*)(\d*\.{0,1}\d*\.{0,1}\d*)'
    match = re.match(regex, product)
    if match:
        product = match.group(1)
        version = match.group(2)
        if version.strip(". ,"): # version is empty, match - for version
            regex = r'(\D*)(\d*)'
            version = match.group(2)
    else:
        product = ""
        version = ""
    return product.strip(". ,"), version.strip(". ,")


# remove root folder from path
def removePath(path):
    path = path.replace(args.folder, "")
    return path


# normalize path name to use / instead of \\ if scanned in windows
def normalizePath(pattern):
    pattern = pattern.replace("\\", "/")
    pattern = pattern.lstrip("/\\.")
    pattern = "/" + pattern
    return pattern


# generate an sbom entry from the given meta data
def genSBOM(meta, product, file, path):
    if args.nopath:
        path = removePath(path)
    app_name = meta.get('app_name')
    target = meta.get('target')
    product, version = extractVersion(product)
    if not product:
        product = target
    ftype = "library" if meta.get('type') == '1' else "binary"
    sbom = {
        'type': ftype,
        'appname': app_name,
        'version': version,
        'libname': target,
        'path': normalizePath(path)
    }
    return sbom


# check if the given filename (fn) is a valid target
# which will be processed, if not valid skip
def is_valid_target_file(fn, dir):
    folders = dir.split(os.path.sep)
    full_path = os.path.join(dir, fn)
    path = os.path.realpath(full_path)
    if (".debug" in folders):
        return False # file is in .debug folder
    elif os.path.islink(path) and args.symlink:
        return False # symlink
    elif full_path not in path and args.symlink:
        return False # symlink
    elif not os.path.isfile(path):
        return False # file doesn't exists
    elif not os.access(path, os.R_OK):
        return False # file cannot be accessed
    elif not fn.startswith("."):
        return True # file does not start with .


# display files that were not matched by any YARA rule 
# undetected packages
def display_no_match_files(file_list):
    logging.info("***Files without matches:")
    for file in file_list:
        logging.info(f"No match: {file}")


# YARA matches will generate SBOM and print results on screen
# if verbose option is enabled
def process_rule_matches(meta, strings, file, file_path, match, SBOM):
    if len(match.strings[0].instances) > 1: # most matches are 2nd string
        strings = str(match.strings[0].instances[1])
    SBOM_entry = genSBOM(meta, strings, file, file_path)
    SBOM.append(SBOM_entry)
    if args.verbose:
        logging.info(f"Rule: {match.rule}")
        logging.info(f"Matches: {match.strings[0].instances[0:20]}")
        logging.info(SBOM_entry)
        logging.info(f"Pattern: {match.meta['pattern']}")


# write SBOM into result file
def write_sbom(SBOM):
    try:
        with open(args.result_file, "w") as f:
            f.write(json.dumps(SBOM))  
    except Exception as e:
        logging.info(f"Error ({type(e)}): Failed to write SBOM to '{args.result_file}'")
        raise e
        

# Recursively scan a folder for files that match the rules
def scan_folder(folder, rules):
    matchCount = 0
    fileCount = 0

    fileNotMatched = []
    SBOM_list = list()

    # recursively scan given folder    
    for root, dirs, files in os.walk(folder): # use followlinks=False to skip symlinks
        for file in files:
            # Check if current file meets rules for scanning
            if is_valid_target_file(file, root):
                file_path = os.path.join(root, file)

                # Pass the filename as an external variable to yara.match()
                try: 
                    matches = rules.match(file_path, externals={'filename': file}, fast=True, timeout=5)
                    #matches = rules.match(file_path, externals={'filename': file})
                except Exception as e:
                    logging.info(f"Error ({type(e)}) - DIR: {root} FILE: {file}  cannot be accessed.")
                    continue

                # increment count of processed files
                fileCount += 1

                # If the file matches the rules, print the filename and rule name
                if matches:
                    for match in matches:
                        process_rule_matches(match.meta, str(match.strings[0].instances[0]), file, file_path, match, SBOM_list)

                        # increment count of detected packages/files
                        matchCount += 1
                else:
                    # store filenames that did not have any matches
                    fileNotMatched.append(file_path)
            else: # skipped file
                logging.info(f"Skipped target - DIR: {root} FILE: {file}")   
    
    write_sbom(SBOM_list)    
    
    if args.verbose:
        display_no_match_files(fileNotMatched)

    print(f"Rule matches: files: {fileCount} matches: {matchCount}")
    logging.info(f"Rule matches: files: {fileCount} matches: {matchCount}")


# load the YARA pattern file 
def load_yara_rules(fn):
    try:
        rules = yara.compile(fn, externals={'filename': 'init'})
        return rules 
    except Exception as e:
        logging.info(f"Error ({type(e)}) - loading YARA pattern file {fn}.")
        exit(0)


def main(args):
    logging.info("Starting the file scanning operation.")

    # Compile the YARA rules from the rule file
    rules = load_yara_rules(args.rule_file)
    yara.set_config(max_match_data = 16)
    yara.set_config(max_strings_per_rule = 20)

    # Call the scan_folder function to start the scan
    scan_folder(args.folder, rules)
    logging.info("File scanning operation completed.")


if __name__ == "__main__":
    start = time.time()
    args = handle_arguments()

    # Configure console logging for verbose output
    if args.verbose:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logging.getLogger().addHandler(console_handler)

    main(args)
    end = time.time()
    logging.info(f"Execution time = {end - start} seconds")
    print(f"Execution time = {end - start}")
