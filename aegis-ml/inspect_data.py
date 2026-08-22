import pandas as pd

df = pd.read_csv("MalMem2022.csv")

print("Shape:", df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

# Check text/object columns — these may contain labels
for col in df.columns:
    if df[col].dtype == "object":
        print("\n" + "=" * 50)
        print("COLUMN:", col)
        print(df[col].value_counts().head(20))