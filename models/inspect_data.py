import pandas as pd
import os

file_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "data",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

df = pd.read_csv(file_path, nrows=10)

print("First 10 rows:")
print(df)

print("\nColumns:")
print(df.columns.tolist())

print("\nData types:")
print(df.dtypes)