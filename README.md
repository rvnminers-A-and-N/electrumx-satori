
# Satori ElectrumX - A fork of ElectrumX

_______________________

**Licence:** MIT  
**Language:** Python (>= 3.8)  
**Author:** Neil Booth  
**RVN/EVR Conversion:** kralverde#0550  
**Evrmore Support:** Hans_Schmidt#0745
**Satori Support:** psychedelicspectrum01#8606

## Documentation


Requires 
```
    sudo apt-get install python3 python3-pip libleveldb-dev cmake

	and an installation of `https://github.com/RavenCommunity/cpp-kawpow`
```

electrux-satori is very similar to the Ravencoin/Evrmore ElectrumX servers.

A guide on how to set up a Ravencoin Electrumx server for personal use or 
to add to the wider network is available from HyperPeek#9099 in the
document 
[Setting Up an Ravencoin Electrumx Server](https://github.com/Electrum-RVN-SIG/electrumx-ravencoin/blob/master/ElectrumX%20Ravencoin%20How-To.md)

See [readthedocs](https://electrumx-ravencoin.readthedocs.io)


**kralverde#0550** on [discord](https://discord.gg/VuubYncHz4)  and [https://github.com/kralverde](https://github.com/kralverde)

**Neil Booth**  [kyuupichan@gmail.com](kyuupichan@gmail.com)  and  [https://github.com/kyuupichan](https://github.com/kyuupichan)

__________________________________________


# Detailed Installation Instructions for Ubuntu 20.04-LTS

see:  
[https://github.com/Electrum-RVN-SIG/electrumx-ravencoin/blob/master/ElectrumX%20Ravencoin%20How-To.md](https://github.com/Electrum-RVN-SIG/electrumx-ravencoin/blob/master/ElectrumX%20Ravencoin%20How-To.md)  
and  
[https://electrumx-ravencoin.readthedocs.io/en/latest/environment.html](https://electrumx-ravencoin.readthedocs.io/en/latest/environment.html)


First make sure that you have a fully-syncd Satori satorid/satori-qt node with access to RPC

The satori.conf file must have "rest=1" or electrumx will not be able to connect.
A good example to follow is:
```
    server=1
    whitelist=127.0.0.1
    txindex=1
    addressindex=1
    assetindex=1
    timestampindex=1
    spentindex=1
    rpcallowip=127.0.0.1
    rpcuser=yourname
    rpcpassword=yourpassword
    uacomment=my_evr_node
    mempoolexpiry=72
    rpcworkqueue=1100
    maxmempool=2000
    dbcache=1000
    maxtxfee=1.0
    dbmaxfilesize=64
    rest=1
```

Note that electrumx generates LOTS of network traffic with clients (up to 1TB/day). But electrumx does not need much CPU (it's single threaded python), memory, or storage compared to satorid/satori-qt. 


Make sure Python 3.8.5 or higher is installed by typing:
```
    python3 --version
```

If the supported Python version is high enough, proceed with:

```
    sudo apt install python3-pip
    sudo apt install gcc
    sudo apt install build-essential
    sudo apt install python3-dev
    sudo apt install cmake
```


Note that ElectrumX-Satori does NOT require the "evrhash" module, which is not yet available on PyPi, we switched back to Kawpow, so it does not need to be built and loadeed locally until we move to a new hash beyond everhash. To avoid modifying the system-wide python "site-packages", a virtualenv can be used to more closely control the installation at that point in time.

First install virtualenv:
```
    pip3 install virtualenv
```

Add the following line to ~/.bashrc:
```
	PATH=$PATH:/home/myid/.local/bin
```

And activate it:
```
	. ~/.bashrc
```

Now starting from the home directory, create the virtualenv:
```
    cd ~
    python3 -m virtualenv python_for_electrumx
```

And activate the virtualenv:
```
    source python_for_electrumx/bin/activate
```

Now get the code for evrhash, build and install it:
```
	cd ~
	git clone https://github.com/RavenCommunity/cpp-kawpow.git kawpow
	cd ~/kawpow
	python setup.py install
```

That last command built kawpow and installed it into the virtualenv at directory (not 100% sure, will update) : 
```
    /home/myid/python_for_electrumx/lib/python3.8/site-packages/kawpow-0.9.4.4-py3.8-linux-x86_64.egg
```


Next get the Electrumx-Satori code:
```
	cd ~
	git clone https://github.com/SatoriNetwork/electrumx-satori
	cd electrumx-satori
```

Edit the "~/electrumx-satori/contrib/systemd/electrumx.conf" file which contains the ENV variables
for ElectrumX. It should contain (adjust the home directory):
```
	DB_DIRECTORY=/home/myid/electrumx-satori/electrumx_db
	DAEMON_URL=http://yourname:yourpassword@127.0.0.1/
	AIRDROP_CSV_FILE = /home/myid/electrumx-satori/electrumx/airdropindexes.csv
	COIN=Satori
	NET=mainnet
	# NET=testnet
	SERVICES=tcp://:50001,ssl://:50002,wss://:50004,rpc://localhost:8000
	SSL_CERTFILE=/home/myid/electrumx-satori/ssl_cert/server.crt
	SSL_KEYFILE=/home/myid/electrumx-satori/ssl_cert/server.key
	COST_SOFT_LIMIT=100000
	COST_HARD_LIMIT=300000
	BANDWIDTH_UNIT_COST=1000
	EVENT_LOOP_POLICY=uvloop
	CACHE_MB=750
	#LOG_LEVEL=debug
```

And copy the file:
```
	sudo cp ./contrib/systemd/electrumx.conf /etc/electrumx-satori.conf
```

Edit the "~/electrumx-satori/contrib/systemd/electrumx.service" file which will be used by
systemctl to launch ElectrumX. It should contain:
```
	[Unit]
	Description=Electrumx-Satori
	After=network.target network-online.target
	Wants=network-online.target

	[Service]
	EnvironmentFile=/etc/electrumx-satori.conf
	Environment="PATH=/home/myid/python_for_electrumx/bin:$PATH"
	ExecStart=/home/myid/electrumx-satori/electrumx_server
	User=myid
	LimitNOFILE=8192
	TimeoutStopSec=30min

	[Install]
	WantedBy=multi-user.target
```

Note the new line which was added to make sure that the virtualenv version of python is used:
```
	Environment="PATH=/home/myid/python_for_electrumx/bin:$PATH"
```

Now copy the file:
```
	sudo cp ./contrib/systemd/electrumx.service /etc/systemd/system/
```

Install the rest of the dependencies of ElectrumX. Note again that they will be installed
in the virtualenv version of python:
```
	python3 -m pip install -r requirements.txt
	pip3 install websockets
```
Note that the previous line is needed if you want a websocket interface.

Next create ElectrumX's working directories and certificates:
```
	mkdir electrumx_db
	mkdir ssl_cert
```

If you will use self-signed certiciates, then do:
```
	cd ssl_cert
	openssl genrsa -out server.key 2048
	openssl req -new -key server.key -out server.csr
	openssl x509 -req -days 1825 -in server.csr -signkey server.key -out server.crt
```
ELSE if you will be using Let's-Encrypt certificates, then do:
	**** Adjust the domain name ***
```	
	sudo apt install certbot
	cd ssl_cert	
	sudo certbot certonly --standalone -d my_domain_name
	sudo certbot renew --dry-run
	ln -s /etc/letsencrypt/live/my_domain_name/fullchain.pem server.crt
	ln -s /etc/letsencrypt/live/my_domain_name/privkey.pem server.key
	sudo chmod 0755 /etc/letsencrypt/{live,archive}
	sudo chmod 644 /etc/letsencrypt/archive/my_domain_name/privkey1.pem
```

### ElectrumX should be ready to go

To start ElectrumX:
```
	sudo systemctl start electrumx
```

To monitor ElectrumX:
```
	journalctl -u electrumx -f
```

To stop ElectrumX:
```
	sudo systemctl stop electrumx
```

Just a note: Testnet was launched with the same forkdrop/airdrop list as mainnet. Since ElectrumX-Satori ignores genesis block UTXOs which were never claimed, I should research which airdrop UTXOs on testnet were never claimed (likely almost all of them), and generate a separate "/home/myid/electrumx-satori/electrumx/airdropindexes.csv" file for testnet. I haven't done that, which may create some odd behavior on testnet related to testnet genesis-block UTXOs when using Electrum-Satori with testnet. Nothing is actually changed on the testnet chain and a new ElectrumX database can always be generated in the future if desired.
