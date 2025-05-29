import subprocess
import platform

def ping_host(host):
    param = '-t' if platform.system().lower() == 'windows' else ''
    command = ['ping', param, host] if param else ['ping', host]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    try:
        for line in process.stdout:
            yield line
    finally:
        process.kill()