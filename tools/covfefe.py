import subprocess


filepath = "data/lua_1_fixed.bin"

result = subprocess.run(["./luadec", filepath], text=True)

if result.returncode == 0:
    print(result.stdout)
else:
    print("Decompilation failed with error code:", result.returncode)
    print("Error message:", result.stderr)

