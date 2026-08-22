import pandas as pd

df = pd.read_csv("MalMem2022.csv")

print("CLASS COUNTS:")
print(df["Class"].value_counts())

print("\nCATEGORY COUNTS:")
print(df["Category"].value_counts())