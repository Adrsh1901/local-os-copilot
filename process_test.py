import psutil

processes = []

for process in psutil.process_iter(['pid', 'name']):
    try:
        cpu = process.cpu_percent(interval=None)

        processes.append({
            "pid": process.info["pid"],
            "name": process.info["name"],
            "cpu": cpu,
            "memory": process.memory_percent()
        })

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

psutil.cpu_percent(interval=1)

for process in processes:
    try:
        p = psutil.Process(process["pid"])
        process["cpu"] = p.cpu_percent(interval=None)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        process["cpu"] = 0

processes = [
    p for p in processes
    if p["pid"] != 0
]

top_cpu = sorted(
    processes,
    key=lambda x: x["cpu"],
    reverse=True
)[:5]

print("Top CPU-consuming processes:\n")

for process in top_cpu:
    print(
        f'{process["pid"]:>6} '
        f'{process["name"]:<25} '
        f'CPU: {process["cpu"]:>6.2f}% '
        f'RAM: {process["memory"]:>6.2f}%'
    )