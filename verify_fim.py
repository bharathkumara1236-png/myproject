from modules.file_checker import save_file_hash, check_file_integrity
import os
import time

def verify_fim():
    test_file = "fim_test.txt"
    
    print("--- 1. Initial Registration ---")
    with open(test_file, "w") as f:
        f.write("Original content")
    
    save_file_hash(test_file)
    result = check_file_integrity(test_file)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Last Saved: {result['last_saved']}")
    
    print("\n--- 2. Modification Detection ---")
    time.sleep(1) # Ensure time difference
    with open(test_file, "w") as f:
        f.write("Modified content!!")
    
    result = check_file_integrity(test_file)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Last Saved: {result['last_saved']}")
    
    print("\n--- 3. Re-registration ---")
    save_file_hash(test_file)
    result = check_file_integrity(test_file)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Last Saved: {result['last_saved']}")
    
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)

if __name__ == "__main__":
    verify_fim()
