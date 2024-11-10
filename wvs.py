import os

def get_system_info():
    command = os.popen('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"').read()
    return command

def check_vulnerabilities(command):
    vuln = ['Windows XP', 'Windows 7', 'Windows 8', 'Windows Server 2003', 'Windows Server 2008']
    vuln1 = ['Windows 7', 'Windows 10', 'Windows Server 2008', 'Windows Server 2012', 'Windows Server 2016', 'Windows Server 2019', 'Windows Server 2022']
    vuln2 = ['Windows 7', 'Windows XP', 'Windows Server 2003', 'Windows Server 2008']
    vuln3 = ['Windows Server 2008', 'Windows Server 2012', 'Windows Server 2016', 'Windows Server 2019']
    vuln4 = ['Windows 10', 'Windows Server 2016', 'Windows Server 2019']

    if command in vuln:
        print('Detected: EternalBlue (SMBv1 Protokolü) - CVE-2017-0144')
    elif command in vuln1:
        print('Detected: PrintNightmare (Print Spooler) - CVE-2021-34527')
    elif command in vuln2:
        print('Detected: BlueKeep (RDP - Remote Desktop Protocol) - CVE-2019-0708')
    elif command in vuln3:
        print('Detected: Zerologon - CVE-2020-1472')
    elif command in vuln4:
        print('Detected: SMBGhost - CVE-2020-0796')
    else:
        print('No known vulnerabilities detected for this OS')

def check_running_services():
    command2 = os.popen('sc query state= all').read()

    if 'Bluetooth Support Service - BlueBorne' in command2:
        print('Vulnerability: BlueBorne (CVE-2017-1000253)')
    elif 'Cryptographic Services - SMBv1' in command2:
        print('Vulnerability: SMBv1 (CVE-2017-0144)')
    elif 'DHCP Client - DHCP Spoofing' in command2:
        print('Vulnerability: DHCP Spoofing (CVE-2018-1123)')
    elif 'File Replication Service' in command2:
        print('Vulnerability: File Replication Service (CVE-2018-0732)')
    elif 'HTTP Service - HTTP.sys' in command2:
        print('Vulnerability: HTTP.sys (CVE-2017-7269)')
    elif 'Microsoft Windows SMB Server' in command2:
        print('Vulnerability: SMBv1 (CVE-2020-0796)')
    else:
        print('No suspicious services detected')

def check_open_ports():
    command3 = os.popen('netstat -an').read()
    if '3389' in command3:
        print('RDP (Remote Desktop Protocol) open - Vulnerable to BlueKeep (CVE-2019-0708)')
    if '139' in command3 or '445' in command3:
        print('SMB open - Vulnerable to EternalBlue (CVE-2017-0144)')
    else:
        print('No vulnerable open ports detected')

def check_firewall_status():
    firewall_status = os.popen('netsh advfirewall show allprofiles').read()
    if 'State                ON' in firewall_status:
        print('Firewall is enabled')
    else:
        print('Firewall is disabled! This may leave the system vulnerable.')


def malware_scan():
    malware_scan_result = os.popen('powershell Get-MpScan').read()
    print("Malware Scan Status:", malware_scan_result)

def main():
    print('Windows Exploit Scanner')

    # Select which command to run
    choice = input('Enter 1 to check OS vulnerability, 2 to check services and vulnerabilities, 3 to check open ports, 4 to check firewall,  5 for malware scan: ')

    if choice == '1':
        system_info = get_system_info()
        print("System Info:", system_info)
        check_vulnerabilities(system_info)
    elif choice == '2':
        check_running_services()
    elif choice == '3':
        check_open_ports()
    elif choice == '4':
        check_firewall_status()
    elif choice == '5':
        malware_scan()
    else:
        print('Invalid option')

if __name__ == '__main__':
    main()
