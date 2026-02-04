in case you use google server with arm, this command will help you to start server

```
#!/bin/bash
sleep 15
apt-get update -y
dpkg -s build-essential &>/dev/null || apt-get install -y build-essential git pkg-config libsecp256k1-dev
REPO_DIR="/root/PrettyWallet"
if [ ! -d "$REPO_DIR" ]; then
    git clone https://github.com/ivotints/PrettyWallet "$REPO_DIR"
else
    cd "$REPO_DIR"
    git pull
fi
cd "$REPO_DIR"
nohup make run &> /dev/null &
```


google provides free 300$ for cloud computing.
It is enough for 24 core vm based on arm archtecture with speed 1 050 000 addr/s for 12 days and nights!
Or, if you will setup Spot VMs, you will get same power, but for 30 days. Just need to setup Instance Group Manager

Also Oracle, AWS and Azure provides with free computing power, but I didn't try that yet.

Also, GPT says it would be much smarter to use GPU for generating private keys... Defenetly should try that in the future.
