# Sock5Proxy
Implementation of the SOCK5 proxy protocol.

## Usage
```powershell
Usage: Sock5Proxy.exe [options]
Options:
  -h, --help               Print this help message.
  -p, --port PORT          Port to host proxy on.
  -u, --username USERNAME  Sets username authentication.
  -P, --password PASSWORD  Sets password authentication.
```

## Example
This implementation is taken from an other project, the Odysseus Sock5 proxy BOF.  
Located at /Odysseus_Sock5Proxy_example_bof.cpp

## Username/Password authentication
For username/Password authentication both the -u and -P option needs to be set. Details about this features are at RFC-1929.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## References
[RFC-1928](https://datatracker.ietf.org/doc/html/rfc1928)
[RFC-1929](https://datatracker.ietf.org/doc/html/rfc1929)