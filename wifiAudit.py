import subprocess

def get_wifi_passwords():
    profiles_data = subprocess.check_output(
        ['netsh', 'wlan', 'show', 'profiles'], text=True
    )
    profiles = [line.split(":")[1].strip() for line in profiles_data.splitlines() if "All User Profile" in line]

    wifi_list = []
    for profile in profiles:
        try:
            profile_info = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], text=True
            )
          
            key_line = [line for line in profile_info.splitlines() if "Key Content" in line]
            password = key_line[0].split(":")[1].strip() if key_line else None
            wifi_list.append({'SSID': profile, 'Password': password})
        except subprocess.CalledProcessError:
            wifi_list.append({'SSID': profile, 'Password': None})

    return wifi_list

if __name__ == "__main__":
    wifi_passwords = get_wifi_passwords()
    for wifi in wifi_passwords:
        print(f"SSID: {wifi['SSID']}, Password: {wifi['Password']}")
