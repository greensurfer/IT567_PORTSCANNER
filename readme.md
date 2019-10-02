# Networking tools for IT567

## Set up

1. Clone/Download the project folder.

2. Setup Virtual Environment

    ```
        sudo mkdir /venv/ && python3 -m venv /venv
    ```
3. Install Dependencies
    ```
       pip3 install -r requirements.txt
    ```

## Usage

sudo python main.py -ip IP_ADDR -p ports -f FILENAME -g FILENAME -m MODE -o FILENAME

-ip - An ip address or range of ip addresses. (i.e.) 192.168.1.0 192.168.1.0/8

-p  - List of ports to scan. (i.e.) 22 53 80 443-445 scans ports 22, 53, 80, 443, 444, 445

-f  - Filename to read ips and ports from.

-g  - Generate a sample file with ips/ports.

-m  - Mode [scan, tcp, udp, scan+tcp, scan+udp] which mode to run.

-o  - Pipe output to HTML file, be sure to specify filename.

-h  - Help, show this in the command prompt.


## Examples

Conduct a TCP port scan of google.com checking for port 22, 25, 53, 80, 443-445.

```
    sudo python main.py -ip 172.217.11.78 -p 22 25 53 80 443-445 -m tcp
```

LAN scan my network using ARP and print IP's, MAC's and Vendor information.

```
    sudo python main.py -ip 192.168.0.0/24 -m scan
```

Create a sample config file to modify.

```
    sudo python main.py -g sample.json
```

Do a LAN scan followed by a TCP port scan. Combine information for print out.

```
    sudo python main.py -ip 172.217.11.78 -p 22 25 53 80 443-445 -m scan+tcp
```
