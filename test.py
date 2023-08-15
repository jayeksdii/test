import yara

fn = "yara_pattern.yar"

try:
    rules = yara.compile(fn, externals={'filename': 'init'})
    print(rules)
except Exception as e:
    print(f"Error ({type(e)}) - loading YARA pattern file {fn}.")
    exit(0)