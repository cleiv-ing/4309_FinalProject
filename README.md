""""NOTE"""": 
  to kill server in powershell if closed terminal on accident: taskkill /PID 12345 /F 
  with 12345 being the PID number you find after running command in terminal: 

netstat -ano | findstr :5000

""""to get this to work on Defense VM and test"""":

1. Attack scripts need to run on Attack VM

2. Install Python on Defense VM

3. Defense VM needs to open terminal inside the folder
  -Run these commands:
  -python -m pip install -r requirements.txt
  -python app.py

4. Cheyenne finds her VM IP
  -On her VM's terminal or powershell use this command: 
  -ipconfig
  -Look for ipv4 address something like 192.168.1.105

5. Test from my laptop browser
  -open the webaddress: http://WHATEVER_HER_VM_IP_IS:5000

6. If it does not load, fix firewall
  -On the Defense VM:
  -Windows Defender Firewall → Advanced Settings → Inbound Rules → New Rule
  -Choose:
  -Port
  -TCP
  -5000
  -Allow connection
  -Name it:
  -Flask Server

7. Change my attack script
-change URL = "http://127.0.0.1:5000/" to URL = "http://VM_IP:5000/"

8. Run the attack from Attack laptop

9. Check logs on Defense VM
-open this file on Defense VM:
-logs/auth.log
