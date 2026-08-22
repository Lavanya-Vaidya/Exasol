import pandas as pd

files = ["Output1.csv", "output2.csv", "output3.csv"]

for file in files:
    df = pd.read_csv(file)

    print("\n" + "=" * 60)
    print("FILE:", file)
    print("=" * 60)

    # Extract the first part of every filename
    print(df["Filename"].str.split("-").str[0].value_counts())

    print("\nSample filenames:")
    print(df["Filename"].sample(
        min(10, len(df)),
        random_state=42
    ).tolist())