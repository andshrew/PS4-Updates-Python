# PS4 Title Update Information

This package retrieves information about the latest update available for a PS4 title. The information is stored in a `Ps4TitleUpdate` object which you can integrate into your Python application. Alternatively it can print this information directly to the screen (for use in a simple CLI application), and it can save the retrieved information as files. This package **does not** download entire PS4 title update files.

## Installation
```
pip install ps4-updates
```

## Typical Usage
Create a `Ps4TitleUpdate` object by specifying a PS4 Title Id (eg. `CUSA00001_00` or `CUSA00001`). A list of known Title Ids is [available here](https://andshrew.github.io/PlayStation-Titles/?platform=ps4&hasContentId).

Invoke `get_update()` on the object to begin retrieving information about the update. If an update is available it will try to retrieve the following:

* Title Name
* Update Url
* Current Version
* Content Id
* Download Size
* Update Creation Date
* changeinfo.xml (developer included update notes)
* param.sfo update pkg parameters

## Limitations
Only information about the current update version can be retrieved.

It is not a guarantee that `changeinfo.xml` will be included within the updates pkg file. This package attempts to locate it (and `param.sfo`) by parsing the update PKG file header. By default it will download up to the first 50MB of the PKG file, but if either the `changeinfo.xml` or `param.sfo` are located beyond this range then neither will be downloaded and no more data will be downloaded beyond the range of the PKG header. You can increase (or decrease) this limit by setting the `byte_limit` when creating a `Ps4TitleUpdate` object.

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
| update_pkg_param_sfo | An `SFO` object if the pkg param.sfo file was found and parsed |
| update_pkg_bytes_exceeded | `True` if the pkg file header was parsed but data exists beyond the range of the specified `bytes_limit` |
| changeinfo_exists | `True` if changeinfo.xml was found |
| changeinfo | List of dicts for each change in changeinfo.xml |
| changeinfo_count | Number of changes in changeinfo.xml |
| changeinfo_current_exists | `True` if a change matching the current version number was in changeinfo.xml |
| changeinfo_current | List of dicts for change matching the current version |
| changeinfo_xml | Full XML for changeinfo.xml

## `SFO` and `SFO_Entry` Object Reference
By default, if an update exists then `get_update()` will download and attempt to parse the beginning of the updates pkg file. If the [`param.sfo`](https://www.psdevwiki.com/ps4/Param.sfo) file is located then the entries that it contains will be parsed into `SFO_Entry` objects and attached to a single `SFO` object that is then accessible from the `update_pkg_param_sfo` attribute of a `Ps4TitleUpdate` object.  

For details of the information that might be in these objects, see the [Parameter Descriptions on psdevwiki.com](https://www.psdevwiki.com/ps4/Param.sfo#Parameters_Descriptions).  

The entries data (as bytes) is saved in the `SFO_Entry` objects `data_bytes` attribute. Your application will need to further parse this information into a usable format.  

### Example for parsing the SAVE_DATA_TRANSFER_TITLE_ID_LIST parameter
There will be an entry in the param.sfo file named `SAVE_DATA_TRANSFER_TITLE_ID_LIST` if the title supports reading another titles save data files (ie. for save transfer between games).  

This example will print a titles update information to the screen, and then additionally print information from this specific SFO entry (if it exists).

```python
from ps4_updates import title as ps4up

title = ps4up.Ps4TitleUpdate('CUSA00897')
title.get_update()
title.print_update_info()

if title.update_pkg_exists is True:
    entry = next((x for x in title.update_pkg_param_sfo.entries if x.name == "SAVE_DATA_TRANSFER_TITLE_ID_LIST"), None)
    if entry is not None:
        entry = entry.data_bytes.decode().strip('\x00').split('\n')
        if len(entry) == 1:
            print(f'This title shares save data with {len(entry)} title:')
        if len(entry) > 1:
            print(f'This title shares save data with {len(entry)} titles:')
        if len(entry) > 0:
            entry = sorted(entry, key=lambda x: x)
            for i in entry:
                print(f'\t{i}')
```
#### Console Output
```
Title Id: CUSA00897
Update Url: http://gs-sec.ww.np.dl.playstation.net/plo/np/CUSA00897/7d49cb7e0fd38b63970664874c3f4149fd86446456cc020a6555afaa79a10239/CUSA00897-ver.xml
Title Name: inFAMOUS™ First Light
Content Id: EP9000-CUSA00897_00-FIRSTLIGHTSHIP00
Current Version: 01.04
Download Size: 2.38 GB
Creation Date: Fri, 18-Nov-2016

01.04
- Graphics Bug Fixes

This title shares save data with 5 titles:
        CUSA00004
        CUSA00223
        CUSA00263
        CUSA00305
        CUSA00309
```

## Additional Thanks
[Zer0xFF](https://gist.github.com/Zer0xFF/d94818f15e3e85b0b4d48000a4be1c73) - sharing the method for generating a title update URL  
[psdevwiki](https://www.psdevwiki.com/ps4) - documentation on [PKG file format](https://www.psdevwiki.com/ps4/PKG_files) and [param.sfo files](https://www.psdevwiki.com/ps4/Param.sfo)