# pwngrid-api

[![PyPI](https://img.shields.io/pypi/v/pwngrid-api.svg)](https://pypi.org/project/pwngrid-api/) ![Python 3.6, 3.7, 3.8](https://img.shields.io/pypi/pyversions/pwngrid-api.svg)

[Pwnagotchi](https://pwnagotchi.ai/)'s Pwngrid API client (⌐■_■)

- https://pwnagotchi.ai/api/grid/

```
$ pip install pwngrid-api
```

## Example
```python
import pwngrid_api


try:
    private_key = pwngrid_api.utils.load_key("./id_rsa_client")
except FileNotFoundError:
    private_key = pwngrid_api.utils.gen_key()
    pwngrid_api.utils.save_key(private_key, "./id_rsa_client")

pwngrid = pwngrid_api.PwngridClient("pygotchi", private_key)
print(pwngrid.unit.identity)

pwngrid.enroll()

pwngrid.send_message(
    recipient="94b67781c4057533d2e2700a9fcce924fbcfc0abf57724415ebc6819a51e4e39",
    cleartext=b"Hello World!",
)

for m in pwngrid.get_inbox()["messages"]:
    data, cleartext, sender = pwngrid.read_message(m["id"])
    print(sender.identity, cleartext.decode("utf-8"))
```
