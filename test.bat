:: Run keyhunt with debug, capture output and pause so window stays open
:: Removes quiet (-q) and enables debug (-d) to show diagnostics
keyhunt.exe -d -m address -f tests/66.txt -b 66 -l compress -R -s 10 -t4 > run.log 2>&1
type run.log
pause