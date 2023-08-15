import os
import time
import json
import argparse


def get_unique_rule_name(appname, rules):
    # Ensure rule name is unique (no duplicates)
    # Remove invalid characters such as '-' and convert to '_'
    appname = appname.replace("-", "_")
    appname = appname.replace(".", "_")
    if appname not in rules:
        rules.add(appname)
        return appname
    else:
        ext = 1
        while f"{appname}_{ext}" in rules:
            ext += 1
        unique_name = f"{appname}_{ext}"
        rules.add(unique_name)
        return unique_name


def normalize_orig_svs(pattern):
    pattern = pattern.replace("\\", "\\\\")
    return pattern


def normalize_svs(pattern):
    # patch/fix non-compatible patterns
    pattern = pattern.replace("/", "\\/")
    pattern = pattern.replace("\\\\", "\\")
    pattern = pattern.replace("$", "")
    pattern = pattern.replace("^", "")

    # Optimizations
    #pattern = pattern.replace("(([0-9]+\.){1,}[0-9]+)", "(([0-9]{1,4}\.){1,}[0-9]{1,4})")
    #pattern = pattern.replace("([0-9]+(\.[0-9]+)*)","([0-9]{1,4}(\.[0-9]{1,4}){0,3})")
    #pattern = pattern.replace("([0-9]+\.[0-9]+\.[0-9]+)","([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})")
    #pattern = pattern.replace("([0-9]+\.[0-9]+)","([0-9]{1,4}\.[0-9]{1,4})") 
    #pattern = pattern.replace("([0-9]\.[0-9]+(\.[0-9]+)?)","([0-9]\.[0-9]{1,4}(\.[0-9]{1,4})?)")

    # replace greedy quantifiers with non-greedy quantifiers
    pattern = pattern.replace("[0-9]+", "[0-9]{1,4}")
    pattern = pattern.replace("[0-9]*", "[0-9]{0,4}")
    return pattern


def normalize_target(target):
    target = target.replace("+", "\\+")
    target = target.replace("[", "\\[")
    return target


def svs_to_yar(item, yar_file, rules):
    ftype = item['type'] # 1 - library - re-match filename, 2 - binary - exact filename match
    target_orig = item['target'] # filename
    target = normalize_target(target_orig)
    
    if ftype == 1:
        target += ".so"
        file_name_rule = f"filename matches /{target}(\\.\\d+)*/ and"
    elif ftype == 2: # exact filename match for binary type
        file_name_rule = f"filename matches /{target}/ and"
    
    appname = item['appname']  # if used for rulename, must be unique
    rulename = get_unique_rule_name(appname, rules)
    orig_pattern = item['pattern']
    pattern = normalize_svs(orig_pattern)
    orig_pattern = normalize_orig_svs(orig_pattern)
    section = item['section']
    version = pattern
    
    if 1 <= ftype <= 2:
        elf_header = "\n\t\t$elf_header = {7F 45 4C 46}"
        elf_rule = "\n\t\t$elf_header at 0 and"
        elf_section = f"for any section in elf.sections: ((section.name == \"{section}\") and $pattern in (section.offset..(section.offset + section.size)))"
        #elfSection = f"for any section in elf.sections: ((section.type != elf.SHT_NOBITS) and (section.name == \"{section}\") and $pattern in (section.address..section.address + section.size))"
        #elfSection = f"for 1 section in elf.sections: ((section.name == \"{section}\") and $pattern in (section.offset..section.offset + section.size \\ 3))"
        # bad but works elfSection = f"for any i in (0..elf.number_of_segments) : ((elf.sections[i].name == \"{section}\") and ($pattern in (elf.sections[i].offset..(elf.sections[i].offset+elf.sections[i].size))))"
    else:
        elf_header = ""
        elf_rule = ""
        elf_section = "$pattern"
    
    template = f"""\nrule {rulename} {{
    meta:
        app_name = "{appname}"
        type = "{ftype}"
        target = "{target_orig}"
        pattern = "{orig_pattern}"

    strings:
        $pattern = /{pattern}/ {elf_header}
        
    condition:
        {file_name_rule}{elf_rule}
        {elf_section}
}}

"""
    yar_file.write(template)


def convert_svs_to_yara(svs_file, yara_file):
    rules = set()
    p1 = load_pattern(svs_file)
    old = p1['static']
    write_yara_file_header(yara_file)
    pattern_count = 0
    
    for item in old:
        svs_to_yar(item, yara_file, rules)
        pattern_count += 1
    
    return pattern_count


def load_pattern(file_path):
    with open(file_path) as f:
        return json.load(f)


def write_yara_file_header(file):
    template = """import "elf"
    
private global rule SizeLimit
{
    condition:
        filesize < 10MB
}
"""
    file.write(template)


def main():
    parser = argparse.ArgumentParser(description="Convert SVS Pattern to a YARA pattern.")
    parser.add_argument("svs_pattern", help="Filename of SVS pattern to convert.")
    parser.add_argument("yara_pattern", help="The filename for the YARA pattern.")
    args = parser.parse_args()

    svs_file = args.svs_pattern
    yara_file = args.yara_pattern

    if svs_file == "--help":
        parser.print_help()
        return

    start_time = time.time()
    with open(yara_file, 'w') as yara:
        pattern_count = convert_svs_to_yara(svs_file, yara)
    end_time = time.time()

    print(f"Finished converting {pattern_count} patterns")
    print(f"Execution time = {end_time - start_time}")


if __name__ == "__main__":
    main()
