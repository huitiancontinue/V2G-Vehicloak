rm -rf signer1/data/geth signer1/data/SN

geth --datadir signer1/data init pow.json

geth --datadir signer1/data --networkid 55661 --port 2007 --unlock 9ebef5ac8cc53c64372dcc3e1037fdd669841bad --password signer1/passwd.txt --cache 2048 console
