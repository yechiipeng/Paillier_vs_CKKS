import csv
import time
import psutil
import os
from threading import Lock
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

metrics_lock = Lock()

def log_metrics(filename, fieldnames, row):
    with metrics_lock:
        file_exists = os.path.isfile(filename)
        with open(filename, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

def get_cpu_ram():
    process = psutil.Process(os.getpid())
    cpu = psutil.cpu_percent(interval=0.1)
    ram = process.memory_info().rss / (1024 * 1024)  # MB
    return cpu, ram

def get_ciphertext_size(ciphertext):
    # For Paillier: ciphertext is usually an int or object
    try:
        return len(str(ciphertext))
    except Exception:
        return 0

def get_ckks_ciphertext_size(ciphertext):
    # For CKKS: ciphertext is a base64 string
    return len(ciphertext)

def compute_classification_metrics(y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, pos_label='inside', zero_division=0)
    rec = recall_score(y_true, y_pred, pos_label='inside', zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label='inside', zero_division=0)
    return acc, prec, rec, f1