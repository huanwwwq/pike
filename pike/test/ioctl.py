#
# Copyright (c) 2013, EMC Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Module Name:
#
#        ioctl.py
#
# Abstract:
#
#        Test IOCTLs.  Currently, only FSCTL_VALIDATE_NEGOTIATE_INFO
#
# Authors: Ki Anderson (kimberley.anderson@emc.com)
#          Paul Martin (paul.o.martin@emc.com)
#

import pike.model as model
import pike.smb2 as smb2
import pike.test as test

share_all = smb2.FILE_SHARE_READ | \
            smb2.FILE_SHARE_WRITE | \
            smb2.FILE_SHARE_DELETE
access_rwd = smb2.FILE_READ_DATA | \
             smb2.FILE_WRITE_DATA | \
             smb2.DELETE

class ValidateNegotiateInfo(test.PikeTest):
    def __init__(self, *args, **kwds):
        super(ValidateNegotiateInfo, self).__init__(*args, **kwds)
        self.default_client.dialects = [
                smb2.DIALECT_SMB3_0,
                smb2.DIALECT_SMB3_0_2]

    # VALIDATE_NEGOTIATE_INFO fsctl succeeds for SMB3
    @test.RequireDialect(smb2.DIALECT_SMB3_0, smb2.DIALECT_SMB3_0_2)
    def test_validate_negotiate_smb3(self):
        chan, tree = self.tree_connect()
        chan.validate_negotiate_info(tree)

class TestIOCTL(test.PikeTest):
    def session_bind(self, chan):
        return chan.connection.client.connect(self.server).negotiate().session_setup(self.creds, bind=chan.session)

    def setUp(self):
        self.chan, self.tree = self.tree_connect()

    def tearDown(self):
        self.chan.tree_disconnect(self.tree)
        self.chan.logoff()

    def generic_ioctl_test_case(self):

        filename = "ioctl_test_file.txt"
        content = "Hello"
        fh = self.chan.create(self.tree,
                               filename,
                               access=access_rwd,
                               share=share_all,
                               disposition=smb2.FILE_SUPERSEDE).result()

        bytes_written = self.chan.write(fh, 0, content)

        chan2 = self.session_bind(self.chan)
        rt = self.chan.query_conn_info(fh)

        self.chan.close(fh)

    def test_ioctl_qeury_conn_info(self):
        self.generic_ioctl_test_case()
