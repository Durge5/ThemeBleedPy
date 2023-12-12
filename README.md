A huge thanks to gabe_k for the initial PoC in C#, and actually finding this CVE, this is a remake of his code in python, reusing his stage files.
To see the initial PoC view his page for it here: <https://github.com/gabe-k/themebleed>
# ThemeBleedPy
A proof of concept using python for the CVE-2023-38146 "ThemeBleed".
# Requirements:
This program uses [Impackets SMB server](https://github.com/fortra/impacket) and overrides the smb2Create function and therefore required Impackets functionalities.
```
  Usage:
    Replace {IP-ADDRESS} in the exploit.theme file
    python3 ThemeBleedServer.py - Run the SMB server
    Use the .theme file on a vulnerable windows 11 machine
    As in Gabe's Exploit you need to create a new stage 3 file that is a dll that exports VerifyThemeVersion, the current file only opens Calc.
```

# How it works:
Themebleed starts with a .THEME file that requests for an msstyles file off of the internet.
If the file has a "999" version number is used it will call the ReviseVersionIfNecessary function, which unsafely loads a .dll file, allowing an attacker to load an unchecked library file.
# Why Another PoC?
I put this together because I couldn't get the C# code to compile in linux, probably due to my own ignorance of how it works, I know how to code python though.
# Notable Lines:
Lines 44-53 in ThemeBleedServer.py/overrideSmb2Create - This is where the path change happens <br />
Lines 191-End in ThemeBleedServer.py - Server Creation <br />
Line 13 in exploit.theme - For IP change.
