*Zwickyverse*

This tutorial will demonstrate how to programmatically interact with Zwickyverse with a `python >3.6` client library.
<br>

#### Installation

Install the client library [zwickyverse.py](https://github.com/dmitryduev/zwickyverse/blob/master/zwickyverse.py), 
with `pip` into your environment:

```bash
pip install git+https://github.com/dmitryduev/zwickyverse.git
```

`zwickyverse` is very lightweight and only depends on `pymongo` and `requests`. 
<br>

#### Quick start

Define your server info and the access credentials and connect to it:

```python
from zwickyverse import Private

protocol = 'https'
host = 'private.caltech.edu'
port = 443
username = 'YOUR_USERNAME'
password = 'YOUR_PASSWORD'

p = Private(protocol=protocol, host=host, port=port, username=username, password=password, verbose=False)
```

<span class="badge badge-secondary">Note</span> `Private` object is a context manager, so can be used with a `with` statement:

```python
with Private(protocol=protocol, host=host, port=port, username=username, password=password) as p:
    # do stuff
    pass
```

Set `verbose=True` if you want more feedback from Private.

