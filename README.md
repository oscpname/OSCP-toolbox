# OSCP-toolbox
Give Back to the Community![1](https://github.com/user-attachments/assets/601b198f-8713-47c2-b70d-6432b5ff1ffb)


# Motivation
Well, 2024 dragon year I tried harder and mastered OSCP+. My journey was not easy at all due to personal and professional context and I would like to help others who study at the moment.

# Toolbox
Guys, one thing I learned that it's better to have less but valuable information. So, instead of being overwhelmed by screens of some data I never use and sometimes even cannot evaluate properly I designed my own tools which produce output I expect. As some folks experience difficulties with Active Directory set here I publish instruments which were very helpful for me personally and it was more than enough for exam purposes:
- for enumeration of Windows box
- for enumeration of Active Directory environment
Hope, it could save you sometime

# 1 - Windows box enumeration
In situation when you get to the box and would like to collect basic infomation also looking for some Privilege Escalation paths:
* Non-standard folders
* Interesting files like .txt, .kdbx etc
* Evaluation and ranking of current user privileges
* Full logic of checks for possible UAC bypass
* Other useful info

USAGE - quick:
```powershell
powershell -nologo -ep bypass -file basic_enum.ps1
```

USAGE - heavy, including password search etc:
```powershell
powershell -nologo -ep bypass -file basic_enum.ps1 extended
```

# 2  - Active Directory enumeration
In situation when you have credentials of any AD user you could try to collect some data and make some basic checks:
- Domain Controllers
- MSSQL servers in Active Directory
- Terminal Servers
- All users
- Domain Admins
- Other admins
- Users with SPN set
- Accounts trusted for Delegation
- Unconstrained delegation
- Constrained delegation
- AS-REP roasting
- Kerberoasting
- other useful checks

You would need to have 2 files in the same folder to run these checks
1) This amazing tool to run AD queries via LDAP protocol: https://github.com/tomcarver16/ADSearch 
2) The script from this repo
USAGE:
```powershell
powershell -ep bypass -file AD_enum.ps1
```


