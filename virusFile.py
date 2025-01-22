# Create a file with the EICAR test string
test_file_path = "eicar_test_file.txt"

# EICAR test string
eicar_test_string = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# Write the EICAR test string to a file
with open(test_file_path, "w") as file:
    file.write(eicar_test_string)

print(f"EICAR test file created at: {test_file_path}")
