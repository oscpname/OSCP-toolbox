# OSCP-toolbox
Give Back to the Community

# Motivation
Well, 2024 dragon year I tried harder and mastered OSCP+. My journey was not easy at all due to personal and professional context and I would like to help others who study at the moment.

# Toolbox
Guys, one thing I learned that it's better to have less but valuable information. So, instead of being overwhelmed by screens of some data I never use and even sometime cannot evaluate properly I designed my own tools which produce output I expect. As some folks experience difficulties with Active Directory set here I publish instruments which were very helpful for me personally and it was more than enough for exam purposes:
- for enumeration of Windows box
- for enumeration of Active Directory environment
Hope, it could save you sometime

# 1 - Windows box enumeration
In situation when you get to the box and would like to collect basic infomation also looking for some Privilege Escalation paths
USAGE: 
```powershell
powershell -ep bypass -file basic_enum.ps1
```

# 2  - Active Directory enumeration
In situation when you have credentials of any AD user you could try to collect some data and make some basic checks:
- AS-REP roasting
- Kerberoasting

You would need to have 2 files in the same folder to run these checks
1) This amazing tool to run AD queries via LDAP protocol: https://github.com/tomcarver16/ADSearch 
2) The script from this repo
USAGE:
```powershell
powershell -ep bypass -file AD_enum.ps1
```


