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

Connect to the server running Zwickyverse with your access credentials:

```python
from zwickyverse import Private

protocol = 'https'
host = 'private.caltech.edu'
port = 443
username = 'YOUR_USERNAME'
password = 'YOUR_PASSWORD'

p = Private(protocol=protocol, host=host, port=port, username=username, password=password, verbose=False)
```

Set `verbose=True` if you want more feedback from Private.

<span class="badge badge-secondary">Note</span> `Private` object is a context manager, and can therefore be used 
with a `with` statement:

```python
with Private(protocol=protocol, host=host, port=port, username=username, password=password) as p:
    # do stuff
    pass
```

Add a new project:

```python
p_id = p.add_project(name='Streaks', description='Example streaks', classes=('keep', 'ditch'))
print(f'created project: {p_id}')
```

Add a dataset to the newly created project:

```python
import os
import glob

path = os.path.abspath('./dev')
images = glob.glob(os.path.join(path, '*.jpg'))  # image absolute paths
print(images)

ds_id = p.add_dataset(project_id=p_id, name='Reals', description='Short streaks', files=images)
print(f'created dataset in project {p_id}: {ds_id}')
```

Get metadata of all your projects:

```python
projects = p.get_project()
print(projects)
```

Get metadata for the project created above:

```python
project = p.get_project(project_id=p_id)
print(project)
```

Get classifications for the dataset from this project:

```python
ds = p.get_classifications(project_id=p_id, dataset_id=ds_id)
print(ds)
```

Get classifications for all datasets from this project:

```python
ds = p.get_classifications(project_id=p_id)
print(ds)
```
