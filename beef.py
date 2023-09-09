#!/usr/bin/python3
"""
    BeEFAPI  - Python class to extract data out of a BeEF (The Browser
    Exploitation Framework) http://beefproject.com/ server via the server's
    REST API. Documentation for the API is located at
        https://github.com/beefproject/beef/wiki/BeEF-RESTful-API
    
    Copyright (c) 2023 Jose J. Cintron - l0rddarkf0rce@yahoo.com
    
    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the
    Free Software Foundation; either version 3 of the License, or (at your
    option) any later version.
    
    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
    more details.
    
    You should have received a copy of the GNU General Public License along
    with this program; if not, see <https://www.gnu.org/licenses/>
"""

import requests
import json

class BeEFAPI:
    """
    Initialize the class. We need (all are mandatory)
          IP: IP address of the server we will be conntecting to.
          UN: User name of the administrator user that was created when the
              server was installed.
          PW: Password of the administrator user.
        PORT: Which port is the server listening on? By default BeEF listens on
              port 3000.
    
    Once we have the above information we get an access token from the server
    that will be used later on to access the API.
    """
    def __init__(self, ip: str = '', un: str = '', pw: str = '', port: int = 3000):
        if (len(ip.strip()) == 0):
            raise ValueError("ERROR: No IP Address provided.")
        elif (port < 1 or port > 65535):
            raise ValueError("ERROR: Invalid port number (1-65535).")
        elif (len(un.strip()) == 0):
            raise ValueError("ERROR: No username provided.")
        elif (len(pw.strip()) == 0):
            raise ValueError("ERROR: No password provided.")
        else:
            self.__ip = ip
            self.__port = port
            self.__un = un
            self.__pw = pw
            self.url = f'http://{self.__ip}:{self.__port}/'
            self.token = self.__getToken(self.__un, self.__pw)
    
    """
    Get the authentication token from the BeEF server.
    """
    def __getToken(self, usr, pwd):
        token = ''
        res = ''
        un_pw = '{"username":"' + f'{self.__un}' + '", "password":"' + f'{self.__pw}' + '"}'
        try:
            res = requests.post(f'{self.url}/api/admin/login', data=un_pw)
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to authenticate to server. Error: {e}.')

        data = json.loads(res.text)
        if ((res.status_code == 200) and (data['success'])):
            token = data['token']
        return (token)

    """
    Print some basic information if the user prints the object.
    """
    def __str__(self):
        browsers = self.getHookedBrowsers()
        offline = browsers['offline']
        online = browsers['online']
        return (f'URL: {self.url}\n   Token: {self.token}\n   Online browsers: {len(online)}\n   Offline Browsers: {len(offline)}')

    """
    Return a JSON object containing a list of all of the hooked browsers.
    """
    def getHookedBrowsers(self):
        res = ''
        browsers = ''
        try:
            res = requests.get(f'{self.url}/api/hooks?token={self.token}')
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to get hooked browsers information. Error: {e}.')

        data = json.loads(res.text)
        if ((res.status_code == 200) and (data)):
            browsers = data['hooked-browsers']
        
        return (browsers)
        
    """
    Get information (browser and OS version, cookies, enabled plugins, etc)
    about a specific hooked browser.
    """
    def getBrowserDetails(self, session):
        try:
            res = json.loads(requests.get(f'{self.url}/api/hooks/{session}?token={self.token}').text)
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to get browsers details. Session: {session} - Error: {e}.')

        return res

    """
    Get  information about all hooked browser's logs, both global and relative.
    """
    def getLogs(self):
        try:
            res = json.loads(requests.get(f'{self.url}/api/logs?token={self.token}').text)
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to get logs. Error: {e}.')

        return res

    """
    Get information about a specified hooked browser's logs.
    """
    def getBrowserLogs(self, session):
        try:
            res = json.loads(requests.get(f'{self.url}/api/logs/{session}?token={self.token}').text)
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to get browsers logs. Session: {session} - Error: {e}.')

        return res

    """
    List all available BeEF command modules.
    """
    def getCommandModules(self):
        try:
            res = json.loads(requests.get(f'{self.url}/api/modules?token={self.token}').text)
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to get list of command modules. Error: {e}.')

        return res

    """
    Get detailed information about a specific BeEF command module.
    """
    def getModuleInfo(self, module):
        try:
            res = json.loads(requests.get(f'{self.url}/api/modules/{module}?token={self.token}').text)
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to get module information. Module: {module} - Error: {e}.')

        return res

    """
    Returns information about a specific previously launched BeEF command
    module.
    """
    def getCommandResult(self, session, module, cmdID):
        try:
            res = json.loads(requests.get(f'{self.url}/api/modules/{session}/{module}/{cmdID}?token={self.token}').text)
        except Exception as e:
            print(f'ERROR: BeEFAPI failed to get command results. Session: {session} - Module: {module} - Command: {cmdID} - Error: {e}.')

        return res

def main():
    # SAMPLE CODE
    beef = BeEFAPI('127.0.0.1', 'foobar', 'foobar', 3000)
    browsers = beef.getHookedBrowsers()
    print(browsers,'\n\n\n')

    for x in browsers['offline']:
        print(f"Session: {browsers['offline'][x]['session']}")

if __name__ == "__main__":
    main()