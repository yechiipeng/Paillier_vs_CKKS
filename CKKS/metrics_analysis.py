import csv

def aggregate_metrics(csv_path):
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    # Example: aggregate accuracy, latency, throughput
    metrics = {
        'accuracy': [],
        'precision': [],
        'recall': [],
        'f1': [],
        'latency': [],
        'throughput': [],
        'cpu': [],
        'ram': [],
        'ciphertext_size': [],
        'request_size': [],
        'bandwidth': [],
        'failures': 0
    }
    for row in rows:
        for k in metrics:
            if k in row and row[k] != '':
                if k == 'failures':
                    metrics[k] += int(row[k])
                else:
                    metrics[k].append(float(row[k]))
    # Print averages
    for k in metrics:
        if isinstance(metrics[k], list) and metrics[k]:
            print(f"{k}: {sum(metrics[k])/len(metrics[k]):.4f}")
        else:
            print(f"{k}: {metrics[k]}")