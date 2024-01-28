PHP-backdoor-detector
PHP backdoor detector is a Python toolkit that helps you find malicious hidden suspicious PHP scripts and shells in your site files.

Purpose
It is quite common for hackers to place a "backdoor" on a site they have hacked. A backdoor can give the hacker continued access to the site even if the site owners changes account passwords. Backdoor scripts will vary from 100s of lines of code to 1 or 2 lines of code. This is why I wrote this script. Read the features section to know what makes it special.

Features
Detect malicious and hidden PHP functions
Detect suspicious scripts and expressions
Detect suspicious filenames
Detect obfuscated behaviors
Ability to easily detect web-shells (including one-liners...etc)
Ability to easily detect obfuscated backdoors
Ability to detect weevely
Detailed reports
Beside its functionalities, it also uses API of VirusTotal and ShellRay to scan your files. (All in one)
Requirements
Python 2 at least and requests library installed.

Download
Git clone command git clone https://github.com/exaland/PHP_Backdoor_Scanner.git Download ZIP, or by using wget: wget https://raw.githubusercontent.com/exaland/PHP-backdoor-detector/master/

Usage
All you have to do is point it to the root directory of your website (or any directory that contains the files that need to be scanned). python php-backdoor-detector.py [options] <directory>

Third Parties
ShellRay is used smoothly if you're connected to Internet with no edit, but you may have to SignUp at VirusTotal to copy your api key and paste it at variable apiKey under virustotal function. So that you can use both of them along with script, and get even better results!

That doesn't mean that you have to be connected to Internet in order to use PHP backdoor detector.

Author
Alexandre MAGNIER - Exaland Concept

Thanks to Yassine Addi for Original Source

License
PHP backdoor detector is released under the MIT license.