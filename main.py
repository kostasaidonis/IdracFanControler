import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import time
import logging
import traceback
import os
import subprocess


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('idrac_controller.log'),  # Log to file
        logging.StreamHandler()  # Also log to console
    ]
)
logger = logging.getLogger('idrac_controller')

# Disable SSL warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

disable_warnings(InsecureRequestWarning)



# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class IPMIController:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.ipmitool_path = os.path.join(os.getcwd(),'ipmitool.exe')

    def run_ipmitool_command(self, command_args):
        try:
            command = [self.ipmitool_path, '-I', 'lanplus', '-H', self.host, '-U', self.username, '-P',
                       self.password] + command_args
            logger.debug(f"Running command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                logger.debug(f"Command output: {result.stdout.strip()}")
                return result.stdout.strip()
            else:
                logger.error(f"Command failed with return code {result.returncode}: {result.stderr.strip()}")
                return None
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            logger.error(f"Full error traceback:\n{traceback.format_exc()}")
            return None

    def set_manual_mode(self):
        logger.debug("Attempting to enable manual fan control mode")
        response = self.run_ipmitool_command(['raw', '0x30', '0x30', '0x01', '0x00'])
        if response is not None:
            logger.info("Successfully enabled manual fan control mode")
        else:
            logger.error("Failed to enable manual fan control mode")

    def set_auto_mode(self):
        logger.debug("Attempting to enable auto fan control mode")
        response = self.run_ipmitool_command(['raw', '0x30', '0x30', '0x01', '0x01'])
        if response is not None:
            logger.info("Successfully enabled auto fan control mode")
        else:
            logger.error("Failed to enable auto fan control mode")

    def set_fan_speed(self, speed):
        fan_speed = str(hex(int(speed)))
        logger.debug(f"Attempting to set fan speed: {speed}% (Raw value: {fan_speed}, Hex: {fan_speed})")

        max_retries = 3
        for attempt in range(max_retries):
            # Pass fan speed as hexadecimal value, formatted to fit the expected byte representation
            response = self.run_ipmitool_command(['raw', '0x30', '0x30', '0x02', '0xff', fan_speed])
            if response is not None:
                logger.info(f"Successfully set fan speed to {speed}%")
                break
            else:
                logger.error(f"Attempt {attempt + 1}/{max_retries}: Failed to set fan speed. Retrying...")
                time.sleep(2)
        else:
            logger.error("Exceeded maximum retries to set fan speed. Operation failed.")


class IDRACController:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.base_url = None

    def connect(self, host, username, password):
        self.base_url = f"https://{host}/redfish/v1"
        try:
            logger.info(f"Connecting to iDRAC at {host} using Redfish API...")
            self.session.auth = (username, password)

            # Check service root
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code == 200:
                logger.info("Successfully connected to Redfish API.")
                return True
            else:
                raise Exception(f"Failed to connect to Redfish API: {response.status_code}")
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    def get_thermal_info(self):
        try:
            chassis_url = f"{self.base_url}/Chassis/"
            chassis_response = self.session.get(chassis_url, timeout=10)

            if chassis_response.status_code == 200:
                chassis_data = chassis_response.json()
                members = chassis_data.get("Members", [])
                for member in members:
                    member_url = member.get("@odata.id")
                    thermal_url = f"https://{self.base_url.split('/')[2]}{member_url}/Thermal"

                    thermal_response = self.session.get(thermal_url, timeout=10)
                    if thermal_response.status_code == 200:
                        return thermal_response.json()

            logger.warning("No valid thermal endpoint found.")
            return None
        except Exception as e:
            logger.error(f"Error retrieving thermal info: {str(e)}")
            logger.error(traceback.format_exc())
            return None

    def get_system_info(self):
        try:
            sys_url = f"{self.base_url}/Systems/System.Embedded.1"
            response = self.session.get(sys_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "Model": data.get("Model", "N/A"),
                    "Manufacturer": data.get("Manufacturer", "N/A"),
                    "SerialNumber": data.get("SerialNumber", "N/A"),
                    "PowerState": data.get("PowerState", "N/A"),
                }
            else:
                logger.warning(f"Failed to retrieve system info: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error retrieving system info: {str(e)}")
            logger.error(traceback.format_exc())
            return None


class IDRACApp:
    def __init__(self, root):
        self.root = root
        self.root.title("iDRAC Controller")
        self.idrac = None
        self.ipmi = None

        # Main Frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Login Frame
        login_frame = ttk.LabelFrame(main_frame, text="Login", padding="5")
        login_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(login_frame, text="Host:").grid(row=0, column=0, sticky=tk.W)
        self.host_entry = ttk.Entry(login_frame, width=30)
        self.host_entry.grid(row=0, column=1, padx=5)
        self.host_entry.insert(0, "192.168.1.120")

        ttk.Label(login_frame, text="Username:").grid(row=1, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(login_frame, width=30)
        self.username_entry.grid(row=1, column=1, padx=5)
        self.username_entry.insert(0, "root")

        ttk.Label(login_frame, text="Password:").grid(row=2, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(login_frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=5)

        self.connect_btn = ttk.Button(login_frame, text="Connect", command=self.connect)
        self.connect_btn.grid(row=3, column=0, columnspan=2, pady=5)

        # System Info Frame
        info_frame = ttk.LabelFrame(main_frame, text="System Information", padding="5")
        info_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.info_text = scrolledtext.ScrolledText(info_frame, height=8, width=50, state='disabled')
        self.info_text.grid(row=0, column=0, padx=5, pady=5)

        # Thermal Info Frame
        thermal_frame = ttk.LabelFrame(main_frame, text="Thermal Information", padding="5")
        thermal_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.thermal_text = scrolledtext.ScrolledText(thermal_frame, height=8, width=50, state='disabled')
        self.thermal_text.grid(row=0, column=0, padx=5, pady=5)

        # Fan Control Frame
        fan_frame = ttk.LabelFrame(main_frame, text="Fan Control", padding="5")
        fan_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.manual_control_btn = ttk.Button(fan_frame, text="Enable Manual Control", command=self.enable_manual_mode)
        self.manual_control_btn.grid(row=0, column=0, padx=5, pady=5)

        self.fan_speed_slider = ttk.Scale(fan_frame, from_=20, to=100, orient=tk.HORIZONTAL)
        self.fan_speed_slider.grid(row=0, column=1, padx=5)

        self.set_speed_btn = ttk.Button(fan_frame, text="Set Fan Speed", command=self.set_fan_speed)
        self.set_speed_btn.grid(row=0, column=2, padx=5)

        self.auto_control_btn = ttk.Button(fan_frame, text="Enable Auto Control", command=self.enable_auto_mode)
        self.auto_control_btn.grid(row=1, column=0, columnspan=3, pady=5)

    def connect(self):
        host = self.host_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not all([host, username, password]):
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        try:
            logger.info("Attempting to establish connection")
            self.idrac = IDRACController()
            self.ipmi = IPMIController(host, username, password)

            if self.idrac.connect(host, username, password):
                messagebox.showinfo("Success", "Connected to iDRAC.")
                self.update_info()
        except Exception as e:
            error_msg = f"Failed to connect: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            messagebox.showerror("Error", error_msg)

    def update_info(self):
        try:
            thermal_info = self.idrac.get_thermal_info()
            if thermal_info:
                self.thermal_text.configure(state='normal')
                self.thermal_text.delete(1.0, tk.END)
                fans = thermal_info.get("Fans", [])
                for fan in fans:
                    self.thermal_text.insert(tk.END,
                                             f"Fan: {fan.get('Name', 'N/A')} - {fan.get('Reading', 'N/A')} {fan.get('ReadingUnits', '')}\n")
                temperatures = thermal_info.get("Temperatures", [])
                for temp in temperatures:
                    self.thermal_text.insert(tk.END,
                                             f"Sensor: {temp.get('Name', 'N/A')} - {temp.get('ReadingCelsius', 'N/A')} °C\n")
                self.thermal_text.configure(state='disabled')

                system_info = self.idrac.get_system_info()
                if system_info:
                    self.info_text.configure(state='normal')
                    self.info_text.delete(1.0, tk.END)
                    for key, value in system_info.items():
                        self.info_text.insert(tk.END, f"{key}: {value}\n")
                    self.info_text.configure(state='disabled')

            # Schedule next update
            if hasattr(self, 'idrac') and self.idrac:
                self.root.after(60000, self.update_info)  # 5000 ms = 5 seconds
        except Exception as e:
            logger.error(f"Error updating info: {str(e)}")
            logger.error(traceback.format_exc())

    def enable_manual_mode(self):
        result = self.ipmi.set_manual_mode()
        if result is None:
            messagebox.showinfo("Success", "Manual fan control enabled.")
        else:
            detailed_error = f"Failed to enable manual control: {result}\nCheck log file for details."
            messagebox.showerror("Error", detailed_error)

    def set_fan_speed(self):
        speed = int(self.fan_speed_slider.get())
        result = self.ipmi.set_fan_speed(speed)
        if result is None:
            messagebox.showinfo("Success", f"Fan speed set to {speed}%.")
        else:
            detailed_error = f"Failed to set fan speed: {result}\nCheck log file for details."
            messagebox.showerror("Error", detailed_error)

    def enable_auto_mode(self):
        result = self.ipmi.set_auto_mode()
        if result is None:
            messagebox.showinfo("Success", "Auto fan control enabled.")
        else:
            detailed_error = f"Failed to enable auto control: {result}\nCheck log file for details."
            messagebox.showerror("Error", detailed_error)


def main():
    root = tk.Tk()
    app = IDRACApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()