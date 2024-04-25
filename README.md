# LostProxy

LostProxy is a multi functional proxy for the HTTP, Socks4/4a and Socks5/5h protocols all in one port.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install lostproxy.

```bash
pip install lostproxy
```

## Usage

```bash
usage: lostproxy.py [-h] [-l LISTENER] [-u USER] [-p PASSWORD] [-a] [-v]

A multi functional proxy for HTTP, Socks4/4a and Socks5/5h all in one port.

options:
  -h, --help            show this help message and exit
  -l LISTENER, --listener LISTENER
                        Listening address, example: 0.0.0.0:8080
  -u USER, --user USER  (OPTIONAL) Username for auth, example: Jack
  -p PASSWORD, --password PASSWORD
                        (OPTIONAL) Password for auth, example: Password123
  -a, --allow_localhost
                        (OPTIONAL) Allows localhost and other internal IP ranges.
  -v, --verbose         (OPTIONAL) Displays information about connections and what site they visit.
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.
## License

[MIT](https://choosealicense.com/licenses/mit/)