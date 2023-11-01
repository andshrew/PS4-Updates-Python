# PS4 Title Update Information

This package retrieves information about the latest update available for a PS4 title. The information is stored in a `Ps4TitleUpdate` object which you can integrate into your Python application. Alternatively it can print this information directly to the screen (for use in a simple CLI application), and it can save the retrieved information as files. This package **does not** download entire PS4 title update files.

## Installation
```
pip install ps4-updates
```

## Typical Usage
Create a `Ps4TitleUpdate` object by specifying a PS4 Title Id (eg. `CUSA00001_00` or `CUSA00001`). 

Invoke `get_update()` on the object to begin retrieving information about the update. If an update is available it will try to retrieve the following:

* Title Name
* Update Url
* Current Version
* Content Id
* Download Size
* Update Creation Date
* changeinfo.xml (developer included update notes)

## Limitations
Only information about the current update version can be retrieved.

It is not a guarantee that changeinfo.xml will be included within the updates pkg file. The file is typically located at the start of the file, however it does not appear to be in a fixed location. This package attempts to locate it by downloading up to the first 30MB of the pkg file. You can increase (or decrease) this search range by setting `byte_limit` when creating a `Ps4TitleUpdate` object.

## Usage Examples

### Create `Ps4TitleUpdate` object and retrieve update information

```python
from ps4_updates import title as ps4up

title = ps4up.Ps4TitleUpdate('CUSA00001')
title.get_update()
```
See [object attributes reference](#ps4titleupdate-attribute-reference).

### Create `Ps4TitleUpdate` object, retrieve update information, and output to the screen

```python
from ps4_updates import title as ps4up

title = ps4up.Ps4TitleUpdate('CUSA00001')
title.get_update()
title.print_update_info()
```

#### Console Output
```
vscode ➜ /workspaces/PS4-Updates-Python (main) $ python app.py
Title Id: CUSA00001
Update Url: http://gs-sec.ww.np.dl.playstation.net/plo/np/CUSA00001/1123f23c1f00810a5e43fcb409ada7823bc5ad21b357817e314b6c4832cf6f9f/CUSA00001-ver.xml
Title Name: THE PLAYROOM
Content Id: IP9100-CUSA00001_00-PLAYROOM00000000
Current Version: 01.07
Download Size: 34.88 MB
Creation Date: Sat, 25-Oct-2014

01.07
THE PLAYROOM VERSION 1.07

This update makes several stability improvements
to THE PLAYROOM.
```

### Create `Ps4TitleUpdate` object, retrieve update information, and save to file

```python
from ps4_updates import title as ps4up

title = ps4up.Ps4TitleUpdate('CUSA00001')
title.get_update()
title.save_update_info()
```

#### File System Output
```
├── data_dump
│   └── CUSA00001
│       └── 01.07
│           ├── 20141025
│           ├── CUSA00001-ver.xml
│           ├── IP9100-CUSA00001_00-PLAYROOM00000000-A0107-V0100.json
│           └── changeinfo.xml
```
## `Ps4TitleUpdate` Attribute Reference

The following attributes are available on your `Ps4TitleUpdate` after creation:

| Name | Description |
| - | - |
| title_id | PS4 Title Id object was created with |
| update_url | Url for accessing title update |

All of the remaining attributes will be available after invoking `get_update()` - if a title has an update available. 

You can also manually invoke `_parse_update_xml()`, which makes the following available:

| Name | Description |
| - | - |
| update_exists | `True` if the title has an update |
| update_size | Update size as a formatted string |
| name | Title name |
| content_id | Title Content Id |
| update_xml | Full XML response from `update_url` |
| update_pkg_manifest_url | Url for accessing package manifest |

You can manually invoke `_parse_update_pkg_json()`, which makes the following available:

| Name | Description |
| - | - |
| update_pkg_manifest_exists | `True` if `update_pkg_manifest_url` was accessed successfully |
| update_pkg_manifest_json | Full JSON response from `update_pkg_manifest_url` |
| update_pkg_url | Url for accessing update pkg file |

You can manually invoke `_get_partial_pkg_file()`, which makes the following available:

| Name | Description |
| - | - |
| update_pkg_exists | `True` if some data was found in pkg file at `update_pkg_url` |
| update_pkg_cdate | Update creation date as string YYYYMMDD |
| update_pkg_cdate_as_date | Update creation date as datetime |
| changeinfo_exists | `True` if changeinfo.xml was found |
| changeinfo | List of dicts for each change in changeinfo.xml |
| changeinfo_count | Number of changes in changeinfo.xml |
| changeinfo_current_exists | `True` if a change matching the current version number was in changeinfo.xml |
| changeinfo_current | List of dicts for change matching the current version |
| changeinfo_xml | Full XML for changeinfo.xml

## Additional Thanks
[Zer0xFF](https://gist.github.com/Zer0xFF/d94818f15e3e85b0b4d48000a4be1c73) - sharing the method for generating a title update URL