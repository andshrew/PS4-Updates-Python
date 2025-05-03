#   MIT License

#   Copyright (c) 2023, 2025 andshrew
#   https://github.com/andshrew/PS4-Updates-Python

#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:

#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.

#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

import binascii
from datetime import datetime
import hashlib
import hmac
import io
import json
import logging
from pathlib import Path
import socket
import ssl
from urllib.parse import urlparse
import xml.etree.ElementTree as xml
from .pkg import *

import requests

class Ps4TitleUpdate:
    """A simple PS4 title update object.

    Create a simple PS4 title update object by supplying a PS4 title id. Generates URLs required
    for accessing a titles update data, and optionally can attempt to extract the change
    info from the updates pkg file.

    Attributes:
        title_id: A PS4 Title Id like CUSA00001_00
        download_pkg: Download and extract param.sfo and changeinfo from update pkg file
                      Default is 'True'
        byte_limit: Download up to this many bytes of the update pkg file
    """

    def __init__(self, title_id=None, download_pkg=True, byte_limit=50000000):
        self.title_id = title_id.replace("_00", "")
        self.title_id = self.title_id.upper()
        if len(self.title_id) != 9:
            logger.debug(f'Unable to generate url for {self.title_id}')
            raise ValueError('Title Id must be like CUSA00001 or CUSA00001_00')
        self.byte_download_limit = byte_limit
        if isinstance(self.byte_download_limit, int) is not True:
            logger.debug(f'Byte download limit is not an integer: {self.byte_download_limit}')
            raise ValueError('Byte Limit must be an integer')
        self.download_pkg = download_pkg
        self.content_id = None
        self.name = None
        self.version = None
        self.update_url = self.get_update_url()
        self.update_exists = False
        self.update_size = None
        self.update_xml = None
        self.update_pkg_manifest_exists = False
        self.update_pkg_manifest_url = None
        self.update_pkg_manifest_json = None
        self.update_pkg_exists = False
        self.update_pkg_url = False
        self.update_pkg_cdate = None
        self.update_pkg_cdate_as_date = None
        self.update_pkg_param_sfo = None
        self.update_pkg_bytes_exceeded = False
        self.changeinfo_exists = False
        self.changeinfo = None
        self.changeinfo_current = None
        self.changeinfo_current_exists = False
        self.changeinfo_count = 0
        self.changeinfo_xml = None
        self._get_update_run = False

    def get_update_url(self, base_url='http://gs-sec.ww.np.dl.playstation.net/plo/np'):
        """Generate the URL for the titles update XML file

        PS4 titles which have an update available have an XML file published as a predetermined location.
        Generates the URL for this file.

        Attributes:
            base_url: Override the base URL path
                      Optional (should not need to be set)
        """
        # HMAC Key - credit to https://gist.github.com/Zer0xFF/d94818f15e3e85b0b4d48000a4be1c73
        data = f'np_{self.title_id}'.encode()
        key = binascii.unhexlify("AD62E37F905E06BC19593142281C112CEC0E7EC3E97EFDCAEFCDBAAFA6378D84")
        h = hmac.new(key, data, hashlib.sha256)
        url = f'{base_url}/{self.title_id}/{h.hexdigest()}/{self.title_id}-ver.xml'
        logger.debug(f'{self.title_id} generated URL: {url}')
        return url
    
    def _parse_update_xml(self):
        """Internal method for parsing the update XML file

        Determines if an update for the title is available. If it is, the XML file is
        parsed and information of interest stored.
        """

        url = self.update_url
        response = invoke_web_request(url)
        if response == None:
            return
        if response.status_code == 404:
            # No update exists
            return
        
        try:
            update_xml = xml.fromstring(response.text)
        except xml.ParseError as ex:
            logger.error(f'Unable to parse XML: {ex.args}')
            return
        
        # TODO this could be more flexible instead of looking for
        # information is specific locations
        if update_xml.tag != 'titlepatch':
            # Unexpected XML
            logger.error(f'Expected tag "titlepatch" but found "{update_xml.tag}"')
            return

        if update_xml[0][0].tag != 'package':
            # Unexpected XML
            logger.error(f'Expected tag "package" but found "{update_xml.tag}"')
            return

        for element in update_xml[0][0]:
            if element.tag == 'paramsfo':
                self.name = element[0].text
                break

        update_data = update_xml[0][0].attrib
        self.update_exists = True
        self.version = update_data['version']
        self.content_id = update_data['content_id']
        self.update_pkg_manifest_url = update_data['manifest_url']
        self.update_size = 'N/A'
        if 'size' in update_data:
            self.update_size = bytes_to_formatted_filesize(int(update_data['size']))
        self.update_xml = response.text
    
    def _parse_update_pkg_json(self):
        """Internal method for parsing the updates pkg manifest JSON file

        The URL for downloading an update pkg file is stored in the manifest JSON file.
        Determines if the manifest file is available, and extracts the URL to the pkg file.
        """

        url = self.update_pkg_manifest_url
        response = invoke_web_request(url)
        if response == None:
            return
        try:
            package_data = json.loads(response.text)
        except json.JSONDecodeError as ex:
            logger.error(f'Unable to parse JSON: {ex.args}')
            return
        package_piece = package_data['pieces'][0]
        self.update_pkg_manifest_exists = True
        self.update_pkg_url = package_piece['url']
        self.update_pkg_manifest_json = response.text

    def _get_partial_pkg_file(self, url=None, port=80, byte_limit=30000000):
        """Internal method for partially downloading an update pkg file

        The PKG file for an update contains additional information relating to update.
        This method parses the PKG header and file table, and then will download data
        up to the location of the files of interest.
        Currently looks for 'param.sfo' and 'changeinfo.xml'
        """

        self.update_pkg_bytes_exceeded = False
        if url is None:
            url = self.update_pkg_url
        url_parsed = urlparse(url)
        if url_parsed.port != None:
            port=url_parsed.port
        elif url_parsed.scheme == "https":
            port=443
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        try:
            s.connect((url_parsed.hostname, port))
        except socket.timeout as ex:
            logger.error(f'Socket timeout connecting to: {url_parsed.hostname} port {port}')
            return

        if url_parsed.scheme == "https":
            # ssl.CERT_NONE will disable validating server cert (ie. no requirement for issuing CA to be in our trusted CAs)
            # When HTTPS is used by the update servers they are typically using certificates issued by an internal CA, so
            # this validation would fail.
            s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_TLSv1_2)
        s.settimeout(60)
        request = f'GET {url_parsed.path} HTTP/1.1\r\nHost:{url_parsed.hostname}\r\nConnection: close\r\n\r\n'
        s.send(request.encode())

        # Build up the pkg file in the response variable
        response = b''
        bytes_rcvd = 0

        changeinfo_found = False
        changeinfo = None

        cdate_found = False
        cdate = None

        pkg = None
        pkg_magic = b'\x7fCNT'
        sfo = None

        # Locate the PKG file in the downloaded data
        while True:
            chunk = s.recv(4096)
            bytes_rcvd += len(chunk)
            if len(chunk) == 0:
                # No more data
                logger.error(f'PKG file header NOT found - server has no more bytes to send - actual data downloaded {bytes_to_formatted_filesize(bytes_rcvd)}')
                response = None
                break
            response = response + chunk

            if pkg_magic not in response:
                # Sometimes downloads are redirected to specific CDN URL
                if "302 Moved Temporarily" in response[0:100].decode():
                    logger.debug(f'302 Moved Temporarily')
                    response_headers = response.decode().splitlines()
                    for i, c in enumerate(response_headers):
                        if "Location: " in c:
                            redirect_url = urlparse(response_headers[i].replace("Location: ", ""))
                            logger.debug(f'Trying again with URL: {redirect_url.geturl()}')
                            # Call this method again to try and download using the CDN URL
                            return self._get_partial_pkg_file(url=redirect_url.geturl(), byte_limit=byte_limit)
            if pkg_magic in response:
                break
            if bytes_rcvd >= byte_limit:
                logger.error(f'PKG file header NOT found - byte limit {byte_limit} reached - actual bytes downloaded {bytes_rcvd}')
                response = None
                break

        # The PKG file has been found in the response
        if pkg_magic in response:            
            # Discard the initial part of the response, so that response now starts with the PKG file
            offset = response.find(pkg_magic)
            response = response[offset:]
            pkg = PKG(offset = 0)

            # Parse the PKG header
            with io.BytesIO(response) as b:
                pkg.set_from_bytes(b)

            # Continue downloading data up to the end of the PKG files table
            pkg_table_end = pkg.table_offset + (pkg.file_count * 32)
            while pkg_table_end > len(response):
                # Need more bytes
                chunk = s.recv(4096)
                bytes_rcvd += len(chunk)
                if len(chunk) == 0:
                    # No more data
                    logger.debug(f'No more data')
                    break
                response = response + chunk
            
            # Parse the PKG files table
            with io.BytesIO(response) as b:
                b.seek(pkg.table_offset)
                for i in range(pkg.file_count):
                    file = PKG_File()
                    file.unpack_from_bytes(b)
                    pkg.files.append(file)

            # We can now locate files of interest, namely:
            # id    | File
            # ==    | ====
            # 4096  | param.sfo (various PKG metadata including cdate)
            # 4704  | changeinfo.xml (Developer patch notes)

            # Check that downloading the param.sfo and changeinfo.xml won't result in exceeding the byte_limit
            check_end_location = 0
            check = file = next((x for x in pkg.files if x.id == 4704), None)
            if check is not None:
                if check.offset + check.size > check_end_location:
                    check_end_location = check.offset + check.size
            check = file = next((x for x in pkg.files if x.id == 4096), None)
            if check is not None:
                if check.offset + check.size > check_end_location:
                    check_end_location = check.offset + check.size
            if check_end_location == 0:
                logging.info(f'Neither changeinfo.xml or param.sfo are in this PKG file')
                s.close()
                return
            if check_end_location + bytes_rcvd >= byte_limit:
                logger.error(f'changeinfo.xml or param.sfo are located beyond the current byte limit {byte_limit}. ' + \
                             f'Increase {byte_limit} to at least {check_end_location + bytes_rcvd + 1} ' + \
                             f'to download')
                logger.debug(f'In total {bytes_to_formatted_filesize(bytes_rcvd)} of the PKG file was downloaded')
                self.update_pkg_bytes_exceeded = True
                s.close()
                return

            # Locate and parse changeinfo.xml
            file = next((x for x in pkg.files if x.id == 4704), None)
            if file is None:
                logger.debug(f'changeinfo.xml does not exist within the PKG file table')
            if file is not None:
                logger.debug(f'changeinfo.xml is located at offset {file.offset}')
                changeinfo_end = file.offset + file.size
                while changeinfo_end > len(response):
                    # Continue downloading up to the end of the changeinfo.xml files location
                    chunk = s.recv(16384)
                    bytes_rcvd += len(chunk)
                    if len(chunk) == 0:
                        logger.error(f'The server has no more data to transfer, but the end of the changeinfo.xml file has not been received yet')
                        s.close()
                        return
                    response = response + chunk
                try:
                    changeinfo = response[file.offset:changeinfo_end].decode()
                except Exception as ex:
                    logger.error(f'Unable to decode the changeinfo.xml file from the response data: {ex.args}')
                    changeinfo = None

                self.update_pkg_exists = True
                if changeinfo is not None:
                    changeinfo_found = True
                    self.changeinfo_xml = changeinfo
                    self.changeinfo_exists = True
                    self.changeinfo = self._parse_changeinfo_xml(self.changeinfo_xml)
                    # When changeinfo.xml contains update notes for multiple versions, there is
                    # no guarantee on the order. Some developers have theirs ascending, some descending.
                    # Try to sort the list so that the first entry is for the latest version
                    self.changeinfo = sorted(self.changeinfo, key=lambda x: x['app_version'], reverse=True)
                    # There is no guarantee that there are notes for the current version.
                    # Try and find that if it exists.
                    current_change = list(filter(lambda x: x['app_version'] == self.version, self.changeinfo))
                    if len(current_change) > 0:
                        self.changeinfo_current = current_change
                        self.changeinfo_current_exists = True
            
            # Locate and parse param.sfo
            file = next((x for x in pkg.files if x.id == 4096), None)
            if file is None:
                logger.debug(f'param.sfo does not exist within the PKG file table')
            if file is not None:
                logger.debug(f'param.sfo is located at offset {file.offset}')
                sfo_end = file.offset + file.size
                while sfo_end > len(response):
                    # Continue downloading up to the end of the param.sfo files location
                    chunk = s.recv(16384)
                    bytes_rcvd += len(chunk)
                    if len(chunk) == 0:
                        logger.error(f'The server has no more data to transfer, but the end of the param.sfo file has not been received yet')
                        s.close()
                        return
                    response = response + chunk
                sfo_data = response[file.offset:sfo_end]
                sfo = SFO(offset_relative=file.offset)
                with io.BytesIO(sfo_data) as b:
                    sfo.set_from_bytes(b)
                    b.seek(20)
                    # Parse the entry index
                    for i in range(sfo.number_of_entries):
                        entry = SFO_Entry()
                        entry.set_from_bytes(b)
                        sfo.entries.append(entry)
                    sfo.set_entries_name(b)
                    # Parse the entry data
                    for i in range(sfo.number_of_entries):
                        entry = sfo.entries[i]
                        b.seek(sfo.data_table_offset + entry.data_table_offset)
                        entry.data_bytes = b.read(entry.param_length)
                self.update_pkg_param_sfo = sfo
                self.update_pkg_exists = True
                # The cdate is within param.sfo entry "PUBTOOLINFO"
                # This is a comma seperated NULL terminated string of
                # key pair values
                pub_data = next((x for x in sfo.entries if x.name == "PUBTOOLINFO"), None)
                if pub_data is None:
                    logger.debug(f'PUBTOOLINFO does not exist within the param.sfo entries')
                if pub_data is not None:
                    try:
                        data = pub_data.data_bytes.decode()
                    except Exception as ex:
                        logger.error(f'Unable to decode PUBTOOLINFO data: {ex.args}')
                        data = None

                    if data is not None:
                        data = data.split(',')
                        cdate = next((x for x in data if "c_date" in x), None)
                        if cdate is not None:
                            cdate = cdate[7:]
                            cdate_found = True
                            self.update_pkg_exists = True
                            self.update_pkg_cdate = cdate
                            try:
                                self.update_pkg_cdate_as_date = datetime.strptime(self.update_pkg_cdate, '%Y%m%d')
                            except Exception as ex:
                                logger.error(f'Unable to parse cdate into datetime: {self.update_pkg_cdate}')
                                self.update_pkg_cdate = None
        s.close()

        if cdate_found == changeinfo_found == True:
            logger.debug(f'cdate and changeinfo.xml were found')
        logger.debug(f'In total {bytes_to_formatted_filesize(bytes_rcvd)} of the PKG file was downloaded')

        return

    def _parse_changeinfo_xml(self, info_xml):
        """Internal method for parsing changeinfo.xml

        This method attempts to parse a changeinfo.xml file into a list of dicts.
        """

        try:
            changeinfo_xml = xml.fromstring(info_xml)
        except xml.ParseError as ex:
            logger.error(f'Unable to parse XML: {ex.args}')
            return

        if changeinfo_xml.tag != 'changeinfo':
            logger.error(f'Expected tag "changeinfo" but found "{changeinfo_xml.tag}"')

        changes = []
        for change in changeinfo_xml:
            app_version = change.attrib['app_ver']
            change_desc = change.text.strip().splitlines()
            for i, c in enumerate(change_desc):
                change_desc[i] = c.strip()
            changes.append({
                'app_version': app_version,
                'description': change_desc,
            })

        self.changeinfo_count = len(changes)
        if self.changeinfo_count == 0:
            logger.debug(f'No changes found in changeinfo.xml: {info_xml}')
            return

        return changes
    
    def get_update(self, download_pkg=True):
        """Get title update information

        This method retrieves information relating to the titles updates.

        By default, if an update exists, it will download the pkg file to retrieve information
        such as changeinfo.xml and cdate.

        Attributes:
            download_pkg: Disables downloading update pkg file when set to False
                          Default is True
        """

        self._get_update_run = True
        self._parse_update_xml()
        if self.update_exists is True:
            self._parse_update_pkg_json()
        if self.update_pkg_manifest_exists == download_pkg == True:
            self._get_partial_pkg_file(byte_limit=self.byte_download_limit)

    def print_update_info(self, full_changeinfo=False):
        """Output update information to the screen

        Displays information about the title update to the screen.
        Information displayed is dependant on what has been requested so far
        (eg. has the update XML been parsed, has changeinfo been parsed)

        When changeinfo.xml has been parsed the latest version notes are
        displayed. Optionally all version notes included in the pkg can be
        displayed.

        Attributes:
            full_changeinfo: Display the full changeinfo.xml
                             Default displays current version only
        """

        print(f'Title Id: {self.title_id}')
        print(f'Update Url: {self.update_url}')
        if self._get_update_run is True:
            if self.update_exists is True:
                print(f'Title Name: {self.name}')
                print(f'Content Id: {self.content_id}')
                print(f'Current Version: {self.version}')
                print(f'Download Size: {self.update_size}')
            if self.update_pkg_exists is True:
                if self.update_pkg_cdate is not None:
                    print(f'Creation Date: {self.update_pkg_cdate_as_date.strftime("%a, %d-%b-%Y")}')
                if self.changeinfo_count >= 1:
                    print('')
                    change_limit = 1
                    if full_changeinfo is True:
                        change_limit = len(self.changeinfo)
                    changeinfo = self.changeinfo[0:change_limit]
                    if full_changeinfo is False and self.changeinfo_current_exists is True:
                        changeinfo = self.changeinfo_current
                    if full_changeinfo is False and self.changeinfo_current_exists is False:
                        # No update note matching this patch version
                        print(f'No change info for update {self.version}, displaying newest entry in file.')
                        print('')
                    for n, change in enumerate(changeinfo):
                        print(f'{change["app_version"]}')    
                        [print(i) for i in change['description']]
                        if n+1 != change_limit: print('')
                    
            # No updates
            if self.update_exists is False:
                print('')
                print('No updates exist for this title')
        print('')

    def save_update_info(self, base_path="data_dump"):
        """Save title update information as files

        When a title has an update available, this method can save some files associated with the update to disk.
        It will attempt to save the files in 'base_path/title_id/version'

        Files saved:
        changeinfo.xml (update notes, included in update pkg file)
        {title_id}-ver.xml (the main update XML)
        {content_id}-version.json (URLs to the update pkg file)
        {cdate} (creation date, included in update pkg file)

        Note this does not save the update pkg file.

        Attributes:
            base_path: Path where the files should be created
        """

        if self.update_exists is True:
            save_data_to_file(data=self.update_xml, titleid=self.title_id, version=self.version,
                              url=self.update_url, base_path=base_path)
        if self.update_pkg_manifest_exists is True:
            save_data_to_file(data=self.update_pkg_manifest_json, titleid=self.title_id, version=self.version,
                              url=self.update_pkg_manifest_url, base_path=base_path)
        if self.update_pkg_exists is True:
            if self.changeinfo_exists is True:
                save_data_to_file(data=self.changeinfo_xml, titleid=self.title_id, version=self.version,
                              filename='changeinfo.xml', base_path=base_path)
            if self.update_pkg_cdate is not None:
                save_data_to_file(data=self.update_pkg_cdate, titleid=self.title_id, version=self.version,
                              filename=self.update_pkg_cdate, base_path=base_path)

def bytes_to_formatted_filesize(size_in_bytes):
    """Format bytes to file size string (MB/GB)

    Converts file size in bytes to a formatted string in either MB or GB.

    Attributes:
        size_in_bytes: Size as bytes for conversion
    """

    if size_in_bytes > 1073741824:
        return f'{round(size_in_bytes / 1048576 / 1024, 2)} GB'
    return f'{round(size_in_bytes / 1048576, 2)} MB'

def invoke_web_request(url):
    """Invoke a web request
    
    Utility function to create a request to a URL and return the response.

    Attributes:
        url: URL to request
    """

    try:
        urlparse(url)
    except Exception as ex:
        # TODO does not throw exception on invalid URL
        logger.debug(f'Invalid URL?: {ex.args}')
        return
    try:
        req = requests.get(url)
    except requests.exceptions.RequestException as ex:
        logger.error(f'Requests protocol exception for: {url}: {ex.args}')
        return
    except Exception as ex:
        logger.error(f'Unable to request: {url}: {ex.args}')
        return
    return req

def save_data_to_file(data, titleid, version, filename=None, url=None, base_path="data_dump"):
    """Save a string of data to a file

    Utility function to save a string of data to a file. The file is created at:
    {base_path}/{titleid}/{version}/{filename OR url}

    Attributes:
        data: String of data which will be the contents of the file
        titleid: Part of folder path
        version: Part of folder path
        filename: Name for the file - Note not used if url is supplied
        url: Last part of path will be used as the filename
        base_path: Base folder path
    """

    destination_path = Path(base_path)
    destination_path = destination_path.joinpath(titleid, version)
    if destination_path.exists() is False:
        try:
            destination_path.mkdir(parents=True)
            logging.debug(f'Created path: {destination_path}')
        except Exception as ex:
            logging.error(f'Unable to create path: {ex.args}')
            return

    if url is not None:
        filename = url.split('/')[-1]

    full_path = destination_path.joinpath(filename)

    if full_path.exists() is False:
        try:
            full_path.write_text(data)
            logging.debug(f'Created {full_path}')
        except Exception as ex:
            logging.error(f'Unable to write file: {ex.args}')
            return

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    print('https://github.com/andshrew/PS4-Updates-Python')