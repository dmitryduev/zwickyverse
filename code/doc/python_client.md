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

Now you can import the library in your script:

```python
from zwickyverse import Private
```

Define your access credentials:

```python
username = 'YOUR_USERNAME'
password = 'YOUR_PASSWORD'
```

Connect to `private`:

```python
k = Private(username=username, password=password, verbose=False)
```

<span class="badge badge-secondary">Note</span> `Kowalski` object is a context manager, so can be used with a `with` statement:

```python
with Private(username=username, password=password, verbose=False) as k:
    # do stuff
    pass
```

Set `verbose=True` if you want more feedback from Private.

