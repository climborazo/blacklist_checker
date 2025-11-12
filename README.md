# Black List Checker

## Description

Blacklist Checker is a Python script that automates the verification of domains of interest within blacklists.

## Dependencies

* Python  
`sudo spt install python3`
* Pip  
`sudo apt install pip`
* Python Venv  
`sudo apt install python3-venv`
* Pandoc  
`sudo apt install pandoc`
* Latex  
`sudo apt install texlive-latex-base texlive-latex-recommended texlive-fonts-recommended texlive-latex-extra`
* Dns Python  
`pip -r requirements.txt`

* Api Keys (Register for free account on these sites)
* Add Api Key (.bashrc / .zshrc)  
`export SPAMHAUS_DQS_KEY=`  
`export VT_API_KEY=`  
`export GSB_API_KEY=`  
`export URLHAUS_API_KEY=`  
`export ABUSEIPDB_KEY=`  
`export OPENPHISH_FEED_PATH="/home/****/****/blacklist_checker/openphish.txt"`  
`export XFORCE_API_KEY=`  
`export XFORCE_API_PASSWORD=`  
`export THREATFOX_AUTH_KEY=`

## Installing

* Clone the repository.  
`git clone https://github.com/climborazo/blacklist_checker.git`  
* Enter Blacklist Checker Folder  
`cd blacklist_checker`
* Create And Activate Virtual Environment  
`python3 -m venv .venv`  
`. .venv/bin/activate`
* Intstall Requirements  
`pip -r requirements.txt`
* Copy .env  
`cp .env.example config/.env`
* Set  
`set -a; source config/.env; set +a`  
* Inside input folder, rename the domain.txt file according to your preferences and enter the domains to be checked, one per line, also create all the text files you need with the reference name, this will be used to create the report.  
* Verify that the run.py file has execution permissions.

## Executing Script

`./run.py`

## Help

`python3 bl.py -h`

## Note

You can start the bl.py script directly, bypassing the automatic functions of run.py, using this syntax:

`python3 bl.py --input input/****.txt --format (html, csv, json, docx, pdf)`

## Authors

Climborazo

## Version History
* 0.2
    * Automated with Run script
* 0.1
    * Initial Release

## License

This project is licensed under the Gnu General Public License, Version 2.0 - See the LICENSE.md file for details

