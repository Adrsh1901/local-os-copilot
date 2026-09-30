import psutil

print("CPU:", psutil.cpu_percent(), "%")

memory = psutil.virtual_memory()
print("RAM:", memory.percent, "%")

disk = psutil.disk_usage("C:\\")
print("Disk:", disk.percent, "%")