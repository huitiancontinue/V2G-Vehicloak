rm -rf signer2/data/geth signer2/data/SN

geth --datadir signer2/data init pow.json

geth --datadir signer2/data --networkid 55661 --port 2008 --unlock d5c3b3bd6ce4b23115dc3a5b77754b85ea9607ff --password signer2/passwd.txt --cache 2048 console
