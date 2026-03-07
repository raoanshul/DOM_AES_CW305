import chipwhisperer as cw
import json
import time
from collections import defaultdict

BITSTREAM = "/home/raoar/RP_WS/DOM_AES_CW305/vivado/DOM_AES_CW305/DOM_AES_CW305.runs/impl_1/cw305_top.bit"
JSON_FILE = "/home/raoar/RP_WS/DOM_AES_CW305/AES_VALIDATION.json"
AES_DEFINES = "/home/raoar/RP_WS/DOM_AES_CW305/hdl/cw305_aes_defines.v"

print("=====================================")
print("     AES FPGA Validation  ")
print("=====================================")

# Connect to target
print("[*] Initializing CW305 FPGA target...")
target = cw.target(
    None,
    cw.targets.CW305,
    force=True,
    fpga_id="100t",
    platform="cw305",
    bsfile=BITSTREAM,
    defines_files=[AES_DEFINES]
)

print("[✓] FPGA programmed successfully\n")

# Load validation vectors
print("[*] Loading AES validation vectors...")
with open(JSON_FILE, "r") as f:
    aes_validation = json.load(f)

print("[✓] Vectors loaded\n")

total_tests = 0
passed_tests = 0
failed_tests = 0
group_stats = defaultdict(lambda: {"pass": 0, "fail": 0})

failures = []

start_time = time.time()

print("Starting validation...\n")

for group_id, testGroup in enumerate(aes_validation["testGroups"], 1):

    group_name = f"Group-{testGroup['tgId']}"

    for test in testGroup["tests"]:
        total_tests += 1

        key = bytearray.fromhex(test["key"])
        plaintext = bytearray.fromhex(test["pt"])
        expected = bytearray.fromhex(test["ct"])

        target.loadEncryptionKey(key)
        target.loadInput(plaintext)
        target.go()

        ciphertext = target.readOutput()

        if ciphertext == expected:
            passed_tests += 1
            group_stats[group_name]["pass"] += 1
        else:
            failed_tests += 1
            group_stats[group_name]["fail"] += 1

            failures.append({
                "key": key.hex(),
                "plaintext": plaintext.hex(),
                "expected": expected.hex(),
                "received": ciphertext.hex()
            })

end_time = time.time()
elapsed = end_time - start_time

print("\n=====================================")
print("           VALIDATION SUMMARY        ")
print("=====================================")

print(f"Total Tests   : {total_tests}")
print(f"Passed        : {passed_tests}")
print(f"Failed        : {failed_tests}")
print(f"Success Rate  : {(passed_tests/total_tests)*100:.2f}%")
print(f"Time Elapsed  : {elapsed:.2f} sec")

print("=====================================\n")

# Show failures if any
if failures:
    print("❌ Failed Test Cases:")
    for i, f in enumerate(failures[:10], 1):  # show first 10 only
        print(f"\nFailure {i}")
        print(f"Key       : {f['key']}")
        print(f"Plaintext : {f['plaintext']}")
        print(f"Expected  : {f['expected']}")
        print(f"Received  : {f['received']}")
else:
    print("✅ All tests passed successfully!")

print("\nValidation complete.")

target.dis()