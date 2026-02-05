
import os
import sys
import time
import json
import re
import paramiko
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import config


@dataclass
class CapeVMConfig:

    host: str = "192.168.52.137"
    user: str = "cape"
    password: str = "12345"
    port: int = 22
    ssh_timeout: int = 30
    connection_retries: int = 3
    retry_delay: int = 5

    cape_path: str = "/opt/CAPEv2"
    cape_url: str = "http://192.168.52.137:8000"
    cape_port: int = 8000
    yara_path: str = "/opt/CAPEv2/analyzer/windows/data/yara"

    default_sample_path: str = "/home/cape/Downloads/sample.exe"

    submission_timeout: int = 120
    analysis_timeout: int = 600
    max_startup_wait: int = 120


class ProgressIndicator:


    def __init__(self, message: str):
        self.message = message
        self.running = False
        self.chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.current = 0

    def start(self):
        self.running = True
        print(f"{self.message} ", end="", flush=True)

    def stop(self):
        self.running = False
        print()


class CapeSSHClient:


    def __init__(self, config: CapeVMConfig):
        self.config = config
        self.ssh = None
        self.logger = logging.getLogger('CapeSSHClient')

    def connect(self) -> bool:

        for attempt in range(self.config.connection_retries):
            try:
                if attempt > 0:
                    print(f"🔄 Retry attempt {attempt + 1}/{self.config.connection_retries}")
                    time.sleep(self.config.retry_delay)

                print(f"🔌 Connecting to CAPE VM: {self.config.host}")

                self.ssh = paramiko.SSHClient()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                self.ssh.connect(
                    hostname=self.config.host,
                    username=self.config.user,
                    password=self.config.password,
                    port=self.config.port,
                    timeout=self.config.ssh_timeout,
                    look_for_keys=False,
                    allow_agent=False
                )

                stdin, stdout, stderr = self.ssh.exec_command("echo 'Connection test'", timeout=10)
                test_output = stdout.read().decode('utf-8').strip()

                if test_output == "Connection test":
                    print("✅ Connected to VM successfully!")
                    return True
                else:
                    raise Exception("Connection test failed")

            except Exception as e:
                print(f"❌ Connection attempt {attempt + 1} failed: {e}")
                if self.ssh:
                    try:
                        self.ssh.close()
                    except:
                        pass
                    self.ssh = None

        print(f"❌ Failed to connect after {self.config.connection_retries} attempts")
        return False

    def execute_command(self, command: str, timeout: int = 60, check_return_code: bool = True) -> Tuple[str, str, int]:

        if not self.ssh:
            raise Exception("Not connected to VM")

        try:
            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=timeout)

            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            return_code = stdout.channel.recv_exit_status()

            if check_return_code and return_code != 0 and error:
                self.logger.warning(f"Command returned {return_code}: {error}")

            return output, error, return_code

        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            raise

    def check_process_running(self, process_name: str) -> bool:

        try:
            output, _, _ = self.execute_command(f"pgrep -f '{process_name}'", check_return_code=False)
            return bool(output.strip())
        except:
            return False

    def wait_for_process(self, process_name: str, max_wait: int = 60) -> bool:

        progress = ProgressIndicator(f"Waiting for {process_name}")
        progress.start()

        try:
            for i in range(max_wait):
                if self.check_process_running(process_name):
                    progress.stop()
                    print(f"✅ {process_name} started after {i} seconds")
                    return True
                time.sleep(1)

            progress.stop()
            print(f"❌ {process_name} failed to start within {max_wait} seconds")
            return False

        except Exception as e:
            progress.stop()
            print(f"❌ Error waiting for {process_name}: {e}")
            return False

    def close(self):

        if self.ssh:
            try:
                self.ssh.close()
                print("🔌 SSH connection closed")
            except:
                pass
            self.ssh = None


class CapeServiceManager:


    def __init__(self, ssh_client: CapeSSHClient, config: CapeVMConfig):
        self.ssh = ssh_client
        self.config = config

    def start_rooter(self) -> bool:

        try:
            print("🚀 Starting CAPE Rooter...")

            if self.ssh.check_process_running('rooter.py'):
                print("ℹ️ Rooter already running")
                return True

            terminal_command = (
                f'gnome-terminal --title="CAPE Rooter" '
                f'--geometry=80x24+100+100 '
                f'-- bash -c "cd {self.config.cape_path} && '
                f'echo \\"CAPE Rooter Starting...\\" && '
                f'echo \\"{self.config.password}\\" | sudo -S python3 ./utils/rooter.py -g cape; '
                f'echo \\"Rooter finished. Press any key to close...\\"; read -n 1" &'
            )

            self.ssh.execute_command(terminal_command, check_return_code=False)
            print("📺 Rooter terminal launched")

            return self.ssh.wait_for_process('rooter.py', 30)

        except Exception as e:
            print(f"❌ Failed to start rooter: {e}")
            return False

    def start_cuckoo(self) -> bool:

        try:
            print("\n🚀 Starting CAPE Cuckoo...")

            if self.ssh.check_process_running('cuckoo.py'):
                print("ℹ️ Cuckoo already running")
                return True

            terminal_command = (
                f'gnome-terminal --title="CAPE Cuckoo" '
                f'--geometry=80x24+600+100 '
                f'-- bash -c "source ~/.bashrc && '
                f'cd {self.config.cape_path} && '
                f'echo \\"CAPE Cuckoo Starting...\\" && '
                f'export PATH=\\"$HOME/.local/bin:$PATH\\" && '
                f'poetry run python3 cuckoo.py; '
                f'echo \\"Cuckoo finished. Press any key to close...\\"; read -n 1" &'
            )

            self.ssh.execute_command(terminal_command, check_return_code=False)
            print("📺 Cuckoo terminal launched")

            return self.ssh.wait_for_process('cuckoo.py', 60)

        except Exception as e:
            print(f"❌ Failed to start cuckoo: {e}")
            return False

    def start_cape_services(self) -> bool:

        try:
            print("🛡️ Starting CAPE Services...")
            print("=" * 60)

            print("Step 1: Starting Rooter...")
            if not self.start_rooter():
                print("❌ Failed to start Rooter")
                return False

            print("✅ Rooter is running")
            print("-" * 40)

            print("Step 2: Starting Cuckoo...")
            if not self.start_cuckoo():
                print("❌ Failed to start Cuckoo")
                return False

            print("✅ Cuckoo is running")
            print("=" * 60)
            print("🎉 CAPE services are fully operational!")

            return True

        except Exception as e:
            print(f"❌ Failed to start CAPE services: {e}")
            return False

    def stop_cape_services(self) -> bool:

        try:
            print("🛑 Stopping CAPE services...")

            if self.ssh.check_process_running('cuckoo.py'):
                self.ssh.execute_command("pkill -f cuckoo.py", check_return_code=False)
                print("✅ Cuckoo stopped")

            if self.ssh.check_process_running('rooter.py'):
                self.ssh.execute_command(f"echo '{self.config.password}' | sudo -S pkill -f rooter.py", check_return_code=False)
                print("✅ Rooter stopped")

            print("✅ All CAPE services stopped")
            return True

        except Exception as e:
            print(f"❌ Error stopping services: {e}")
            return False

    def show_status(self):

        try:
            print("🔍 CAPE Service Status:")
            print("-" * 40)

            output, _, _ = self.ssh.execute_command("ps aux | grep -E 'rooter\\.py|cuckoo\\.py' | grep -v grep", check_return_code=False)

            rooter_running = "rooter.py" in output
            cuckoo_running = "cuckoo.py" in output

            print(f"Rooter: {'✅ Running' if rooter_running else '❌ Stopped'}")
            print(f"Cuckoo: {'✅ Running' if cuckoo_running else '❌ Stopped'}")
            print(f"Status: {'✅ Ready' if rooter_running and cuckoo_running else '❌ Not Ready'}")

        except Exception as e:
            print(f"❌ Status check failed: {e}")


class CapeSampleSubmitter:


    def __init__(self, ssh_client: CapeSSHClient, config: CapeVMConfig):
        self.ssh = ssh_client
        self.config = config

    def submit_sample(self, sample_path: str, options: str = "") -> Optional[str]:

        try:
            print(f"📤 Submitting sample: {sample_path}")
            if options:
                print(f"🔧 Options: {options}")
            else:
                print(f"🔧 Options: (none)")

            from pathlib import Path
            local_path = Path(sample_path)

            if local_path.exists() and local_path.is_file():
                print(f"📁 Transferring file from Windows to VM...")

                import os
                remote_path = f"/home/{self.config.user}/samples/{local_path.name}"

                self.ssh.execute_command(f"mkdir -p /home/{self.config.user}/samples", check_return_code=False)

                try:
                    sftp = self.ssh.ssh.open_sftp()
                    sftp.put(str(local_path), remote_path)
                    sftp.close()
                    print(f"✅ File transferred to VM: {remote_path}")
                    sample_path = remote_path
                except Exception as e:
                    print(f"❌ Failed to transfer file: {e}")
                    return None
            else:
                output, _, return_code = self.ssh.execute_command(f"ls -la '{sample_path}' 2>/dev/null", check_return_code=False)
                if return_code != 0:
                    sample_path_exe = f"{sample_path}.exe"
                    output, _, return_code = self.ssh.execute_command(f"ls -la '{sample_path_exe}' 2>/dev/null", check_return_code=False)
                    if return_code == 0:
                        print(f"📁 File found with .exe extension: {sample_path_exe}")
                        sample_path = sample_path_exe
                    else:
                        print(f"❌ File not found on VM: {sample_path} (also tried .exe)")
                        return None

            if options:
                submit_command = (
                    f"cd {self.config.cape_path} && "
                    f"source ~/.bashrc && "
                    f"export PATH=\"$HOME/.local/bin:$PATH\" && "
                    f'poetry run python3 utils/submit.py --options "{options}" "{sample_path}"'
                )
            else:
                submit_command = (
                    f"cd {self.config.cape_path} && "
                    f"source ~/.bashrc && "
                    f"export PATH=\"$HOME/.local/bin:$PATH\" && "
                    f'poetry run python3 utils/submit.py "{sample_path}"'
                )

            print(f"🔄 Running submit command...")
            output, error, return_code = self.ssh.execute_command(submit_command, timeout=self.config.submission_timeout)

            if "task with ID" in output:
                task_id_match = re.search(r"task with ID (\d+)", output)
                if task_id_match:
                    task_id = task_id_match.group(1)
                    print(f"✅ Sample submitted, task ID: {task_id}")
                    return task_id

            print(f"❌ Failed to submit sample (return_code={return_code})")
            if output:
                output_preview = output[-500:] if len(output) > 500 else output
                print(f"   Output: {output_preview}")
            if error:
                error_preview = error[-500:] if len(error) > 500 else error
                print(f"   Error: {error_preview}")
            return None

        except Exception as e:
            print(f"❌ Submission error: {e}")
            return None

    def submit_and_wait(self, sample_path: str, options: str = "") -> Optional[str]:

        task_id = self.submit_sample(sample_path, options)

        if not task_id:
            return None

        print("⏳ Waiting for analysis to complete...")

        report_path = f"{self.config.cape_path}/storage/analyses/{task_id}/reports/report.json"
        max_wait = self.config.analysis_timeout
        wait_interval = 20

        progress = ProgressIndicator("Analyzing")
        progress.start()

        for _ in range(max_wait // wait_interval):
            _, _, return_code = self.ssh.execute_command(f"ls {report_path}", check_return_code=False)

            if return_code == 0:
                progress.stop()
                print(f"✅ Analysis completed for task {task_id}")
                time.sleep(5)
                return task_id

            time.sleep(wait_interval)

        progress.stop()
        print(f"⚠️ Analysis timed out after {max_wait} seconds")
        return task_id


class CapeResultsManager:


    def __init__(self, ssh_client: CapeSSHClient, config: CapeVMConfig, vm_name: str = None):
        self.ssh = ssh_client
        self.config = config
        self.vm_name = vm_name or config.host.replace('.', '_')

    def get_analysis_results(self, task_id: str) -> Optional[Dict[str, Any]]:

        try:
            print(f"📥 Retrieving results for task {task_id}")

            local_dir = f"data/results/task_{task_id}_{self.vm_name}"
            os.makedirs(local_dir, exist_ok=True)

            sftp = self.ssh.ssh.open_sftp()

            analysis_data = {}

            main_files = [
                ("reports/report.json", "report.json"),
                ("analysis.log", "analysis.log"),
            ]

            for remote_file, local_file in main_files:
                remote_path = f"{self.config.cape_path}/storage/analyses/{task_id}/{remote_file}"
                local_path = os.path.join(local_dir, local_file)

                try:
                    sftp.get(remote_path, local_path)
                    print(f"  ✅ Downloaded {local_file}")

                    if local_file.endswith('.json'):
                        with open(local_path, 'r', encoding='utf-8') as f:
                            if local_file == "report.json":
                                analysis_data['report'] = json.load(f)

                    elif local_file.endswith('.log') or local_file.endswith('.txt'):
                        with open(local_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        if 'debugger' in local_file:
                            if 'debugger_files' not in analysis_data:
                                analysis_data['debugger_files'] = {}
                            analysis_data['debugger_files'][local_file] = content
                        else:
                            analysis_data[local_file.replace('.log', '_log')] = content

                except Exception as e:
                    print(f"  ⚠️ Could not download {local_file}: {e}")

            debugger_path = f"{self.config.cape_path}/storage/analyses/{task_id}/debugger"
            debugger_local = os.path.join(local_dir, "debugger")

            try:
                output, _, ret = self.ssh.execute_command(f"ls {debugger_path} 2>/dev/null", check_return_code=False)

                if ret == 0 and output.strip():
                    os.makedirs(debugger_local, exist_ok=True)
                    print(f"  📁 Downloading debugger files...")

                    for filename in output.strip().split('\n'):
                        if filename:
                            remote_file = f"{debugger_path}/{filename}"
                            local_file = os.path.join(debugger_local, filename)
                            try:
                                sftp.get(remote_file, local_file)
                                print(f"    ✅ Downloaded debugger/{filename}")

                                with open(local_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if 'debugger_output' not in analysis_data:
                                        analysis_data['debugger_output'] = {}
                                    analysis_data['debugger_output'][filename] = content
                            except Exception as e:
                                print(f"    ⚠️ Could not download debugger/{filename}: {e}")
                else:
                    print(f"  ℹ️ No debugger files found")
            except Exception as e:
                print(f"  ⚠️ Could not access debugger folder: {e}")

            sftp.close()

            if analysis_data:
                combined_file = os.path.join(local_dir, "combined_analysis.json")
                with open(combined_file, 'w', encoding='utf-8') as f:
                    json.dump(analysis_data, f, indent=2)

                print(f"✅ Results saved to {local_dir}")
                return analysis_data
            else:
                print("❌ No analysis data retrieved")
                return None

        except Exception as e:
            print(f"❌ Error retrieving results: {e}")
            return None

    def list_tasks(self) -> List[str]:

        try:
            output, _, _ = self.ssh.execute_command(
                f"ls -la {self.config.cape_path}/storage/analyses/ | grep '^d' | awk '{{print $NF}}' | grep -E '^[0-9]+$'",
                check_return_code=False
            )

            tasks = [line.strip() for line in output.split('\n') if line.strip()]

            if tasks:
                print(f"📋 Found {len(tasks)} analysis tasks")
                return tasks
            else:
                print("ℹ️ No analysis tasks found")
                return []

        except Exception as e:
            print(f"❌ Error listing tasks: {e}")
            return []


class CapeVMController:


    def __init__(self, host: str = None, user: str = None, password: str = None, vm_name: str = None):

        self.config = CapeVMConfig()

        if host:
            self.config.host = host
        if user:
            self.config.user = user
        if password:
            self.config.password = password

        self.vm_name = vm_name or (host.replace('.', '_') if host else 'default')

        self.ssh_client = CapeSSHClient(self.config)
        self.service_manager = CapeServiceManager(self.ssh_client, self.config)
        self.sample_submitter = CapeSampleSubmitter(self.ssh_client, self.config)
        self.results_manager = CapeResultsManager(self.ssh_client, self.config, self.vm_name)

        print(f"🎯 CAPE VM Controller initialized for {self.config.host} (vm_name: {self.vm_name})")

    def connect(self) -> bool:

        return self.ssh_client.connect()

    def start_services(self) -> bool:

        return self.service_manager.start_cape_services()

    def stop_services(self) -> bool:

        return self.service_manager.stop_cape_services()

    def show_status(self):

        self.service_manager.show_status()

    def submit_sample(self, sample_path: str, options: str = "", ensure_services: bool = True) -> Optional[str]:


        if ensure_services:
            print("🔍 Checking CAPE services...")

            rooter_running = self.ssh_client.check_process_running('rooter.py')
            cuckoo_running = self.ssh_client.check_process_running('cuckoo.py')

            if not rooter_running or not cuckoo_running:
                print("⚠️ CAPE services not fully running, starting them...")
                if not self.service_manager.start_cape_services():
                    print("❌ Failed to start CAPE services")
                    return None
                time.sleep(5)
            else:
                print("✅ CAPE services are running")

        return self.sample_submitter.submit_and_wait(sample_path, options)

    def get_results(self, task_id: str) -> Optional[Dict[str, Any]]:

        return self.results_manager.get_analysis_results(task_id)

    def list_tasks(self) -> List[str]:

        return self.results_manager.list_tasks()

    def deploy_yara_rule(self, yara_content: str, filename: str = None) -> bool:

        try:
            if not filename:
                filename = f"rule_{int(time.time())}.yar"

            remote_path = f"{self.config.yara_path}/{filename}"

            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp:
                tmp.write(yara_content)
                tmp_path = tmp.name

            try:
                sftp = self.ssh_client.ssh.open_sftp()
                sftp.put(tmp_path, remote_path)
                sftp.close()

                print(f"✅ Deployed YARA rule to {remote_path}")
                return True

            finally:
                os.unlink(tmp_path)

        except Exception as e:
            print(f"❌ Failed to deploy YARA rule: {e}")
            return False

    def run_complete_analysis(self, sample_path: str, options: str = None) -> Optional[Dict[str, Any]]:

        try:
            if not self.connect():
                return None

            print("\n🔍 Checking CAPE services...")
            rooter_running = self.ssh_client.check_process_running('rooter.py')
            cuckoo_running = self.ssh_client.check_process_running('cuckoo.py')

            if not rooter_running or not cuckoo_running:
                print("⚠️ CAPE services not fully running, starting them...")
                if not self.service_manager.start_cape_services():
                    print("❌ Failed to start CAPE services")
                    return None
                time.sleep(5)
            else:
                print("✅ CAPE services are running")

            task_id = self.submit_sample(sample_path, options, ensure_services=False)
            if not task_id:
                return None

            return self.get_results(task_id)

        except Exception as e:
            print(f"❌ Analysis failed: {e}")
            return None
        finally:
            self.close()

    def close(self):

        self.ssh_client.close()
        print("✅ CAPE VM Controller closed")

    def restart_vm(self) -> bool:

        import subprocess

        vm_host = self.config.host
        print(f"\n{'='*60}")
        print(f"[!] VM RESTART for {vm_host}")
        print(f"{'='*60}")

        vmx_path = config.VM_VMX_MAPPING.get(vm_host)
        if not vmx_path:
            print(f"[!] No VMX path configured for host {vm_host}")
            print(f"    Please update VM_VMX_MAPPING in config/settings.py")
            return False

        vmrun_path = config.VMRUN_PATH

        print(f"[*] Closing existing SSH connection...")
        self.ssh_client.close()

        print(f"[*] Resetting VM: {vmx_path}")
        try:
            result = subprocess.run(
                [vmrun_path, "reset", vmx_path, "hard"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                print(f"[!] vmrun reset failed: {result.stderr}")
                print(f"[*] Trying stop + start as fallback...")
                subprocess.run([vmrun_path, "stop", vmx_path, "hard"],
                              capture_output=True, timeout=30)
                time.sleep(5)
                result = subprocess.run([vmrun_path, "start", vmx_path],
                                       capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    print(f"[!] vmrun start failed: {result.stderr}")
                    return False

            print(f"[+] VM reset command sent successfully")

        except subprocess.TimeoutExpired:
            print(f"[!] vmrun command timed out")
            return False
        except FileNotFoundError:
            print(f"[!] vmrun not found at: {vmrun_path}")
            print(f"    Please update VMRUN_PATH in config/settings.py")
            return False
        except Exception as e:
            print(f"[!] Error running vmrun: {e}")
            return False

        print(f"[*] Waiting for VM to boot...")
        boot_wait = config.VM_RESTART_TIMEOUT
        print(f"    (timeout: {boot_wait} seconds)")

        retry_delay = config.VM_SSH_RETRY_DELAY
        max_retries = config.VM_SSH_MAX_RETRIES

        for attempt in range(1, max_retries + 1):
            print(f"    SSH connection attempt {attempt}/{max_retries}...")
            time.sleep(retry_delay)

            self.ssh_client = CapeSSHClient(self.config)

            if self.ssh_client.connect():
                print(f"[+] SSH connection re-established after VM restart")

                self.service_manager = CapeServiceManager(self.ssh_client, self.config)
                self.sample_submitter = CapeSampleSubmitter(self.ssh_client, self.config)
                self.results_manager = CapeResultsManager(self.ssh_client, self.config, self.vm_name)
                print(f"[+] All components updated with new SSH connection")

                return True

        print(f"[!] Failed to reconnect to VM after {max_retries} attempts")
        return False


def test_cape_vm_controller():

    print("🧪 Testing CAPE VM Controller")
    print("=" * 60)

    controller = CapeVMController()

    print("\n1. Testing connection...")
    if not controller.connect():
        print("❌ Connection test failed")
        return

    print("✅ Connection test passed")

    print("\n2. Checking service status...")
    controller.show_status()

    print("\n3. Listing existing tasks...")
    tasks = controller.list_tasks()
    if tasks:
        print(f"   Found tasks: {tasks[:5]}...")

    controller.close()
    print("\n✅ All tests completed")


if __name__ == "__main__":
    test_cape_vm_controller()