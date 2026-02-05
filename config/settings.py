
class Config:


    OLLAMA_URL = "http://localhost:11434"
    DEFAULT_MODEL = "qwen3:latest"

    CAPE_HOST = "192.168.52.144"
    CAPE_USER = "cape"
    CAPE_PASSWORD = "12345"

    IDA_PATH = r"C:\Program Files\IDA Pro 8.2\ida.exe"
    IDA_64_PATH = r"C:\Program Files\IDA Pro 8.2\ida64.exe"

    OUTPUT_BASE_DIR = "cot_output"
    MAX_ANALYSIS_TIME = 300

    MAX_PATTERNS_TO_ANALYZE = 5

    VMRUN_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

    VM_VMX_MAPPING = {
        "192.168.52.144": r"D:\VMs\c9_1\c9_1.vmx",
        "192.168.52.145": r"D:\VMs\c9_2\c9_2.vmx",
        "192.168.52.147": r"D:\VMs\c9_3\c9_3.vmx",
        "192.168.52.148": r"D:\VMs\c9_4\c9_4.vmx",
    }

    VM_RESTART_TIMEOUT = 180
    VM_SSH_RETRY_DELAY = 10
    VM_SSH_MAX_RETRIES = 18

    def __init__(self):
        pass

config = Config()