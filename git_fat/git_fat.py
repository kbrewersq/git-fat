#!/usr/bin/env python3
# -*- mode:python -*-



import hashlib
import os
import subprocess
import sys
import tempfile
import warnings
import configparser
import logging as _logging  # Use logger.error(), not logging.error()
import shutil
import argparse
import platform
import stat
import threading
try:
    import botocore
except ImportError:
    print("If you intend to use s3 you need to add boto3 to your path")
    boto3 = None
    botocore = None


_logging.basicConfig(format='%(levelname)s:%(filename)s: %(message)s')
logger = _logging.getLogger(__name__)

__version__ = '1.0.0'

BLOCK_SIZE = 4096

NOT_IMPLEMENTED_MESSAGE = "This method isn't implemented for this backend!"


def get_log_level(log_level_string):
    log_level_string = log_level_string.lower()
    if not log_level_string:
        return _logging.WARNING
    levels = {'debug': _logging.DEBUG,
              'info': _logging.INFO,
              'warning': _logging.WARNING,
              'error': _logging.ERROR,
              'critical': _logging.CRITICAL}
    if log_level_string in levels:
        return levels[log_level_string]
    else:
        logger.warning("Invalid log level: {}".format(log_level_string))
    return _logging.WARNING


GIT_FAT_LOG_LEVEL = get_log_level(os.getenv("GIT_FAT_LOG_LEVEL", ""))
GIT_FAT_LOG_FILE = os.getenv("GIT_FAT_LOG_FILE", "")
GIT_SSH = os.getenv("GIT_SSH")


def git(cliargs, *args, **kwargs):
    '''Calls git commands with Popen arguments'''
    if GIT_FAT_LOG_FILE and "--failfast" in sys.argv:
        # Flush any prior logger warning/error/critical to the log file
        # which is being checked by unit tests.
        sys.stdout.flush()
        sys.stderr.flush()
    if GIT_FAT_LOG_LEVEL == _logging.DEBUG:
        logger.debug('{}'.format(' '.join(['git'] + cliargs))
                     + ' ({}, {})'.format(args, kwargs))
    return subprocess.Popen(['git'] + cliargs, *args, **kwargs)


def debug_check_output(args, **kwargs):
    if GIT_FAT_LOG_FILE and "--failfast" in sys.argv:
        # Flush any prior logger warning/error/critical to the log file
        # which is being checked by unit tests.
        sys.stdout.flush()
        sys.stderr.flush()
    if GIT_FAT_LOG_LEVEL == _logging.DEBUG:
        args2 = args
        for i, v in enumerate(args):
            args[i] = v.replace("\x00", r"\x00")
        logger.debug('{}'.format(' '.join(args2)))
    return subprocess.check_output(args, **kwargs)


def mkdir_p(path):
    import errno
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


# -----------------------------------------------------------------------------
# On Windows files may be read only and may require changing
# permissions. Always use these functions for moving/deleting files.

def move_file(src, dst):
    if platform.system() == "Windows":
        if os.path.exists(src) and not os.access(src, os.W_OK):
            st = os.stat(src)
            os.chmod(src, st.st_mode | stat.S_IWUSR)
        if os.path.exists(dst) and not os.access(dst, os.W_OK):
            st = os.stat(dst)
            os.chmod(dst, st.st_mode | stat.S_IWUSR)
    shutil.move(src, dst)


def delete_file(f):
    if platform.system() == "Windows":
        if os.path.exists(f) and not os.access(f, os.W_OK):
            st = os.stat(f)
            os.chmod(f, st.st_mode | stat.S_IWUSR)
    os.remove(f)

# -----------------------------------------------------------------------------


def make_sys_streams_binary():
    # Information for future: in Python 3 use sys.stdin.detach()
    # for both Linux and Windows.
    if platform.system() == "Windows":
        import msvcrt  # pylint: disable=import-error
        result = msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        if result == -1:
            raise Exception("Setting sys.stdin to binary mode failed")
        result = msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        if result == -1:
            raise Exception("Setting sys.stdout to binary mode failed")


def umask():
    '''
    Get umask without changing it.
    '''
    old = os.umask(0)
    os.umask(old)
    return old


def readblocks(stream):
    '''
    Reads BLOCK_SIZE from stream and yields it
    '''
    while True:
        data = stream.read(BLOCK_SIZE)
        if not data:
            break
        yield data


def cat_iter(initer, outstream):
    for block in initer:
        outstream.write(block)


def cat(instream, outstream):
    return cat_iter(readblocks(instream), outstream)


def gitconfig_get(name, cfgfile=None):
    args = ['config', '--get']
    if cfgfile is not None:
        args += ['--file', cfgfile]
    args.append(name)
    p = git(args, stdout=subprocess.PIPE)
    output = p.communicate()[0].strip()
    if p.returncode != 0:
        return ''
    else:
        return output


def gitconfig_set(name, value, cfgfile=None):
    args = ['git', 'config']
    if cfgfile is not None:
        args += ['--file', cfgfile]
    args += [name, value]
    subprocess.check_call(args)


def _config_path(path=None):
    try:
        root = debug_check_output('git rev-parse --show-toplevel'.split(), text=True).strip()
    except subprocess.CalledProcessError:
        raise RuntimeError('git-fat must be run from a git directory')
    default_path = os.path.join(root, '.gitfat')
    return path or default_path


def _obj_dir():
    try:
        gitdir = debug_check_output('git rev-parse --git-dir'.split(), text=True).strip()
    except subprocess.CalledProcessError:
        raise RuntimeError('git-fat must be run from a git directory')
    return os.path.join(gitdir, 'fat', 'objects')


def http_get(baseurl, filename, user=None, password=None):
    ''' Returns file descriptor for http file stream, catches urllib2 errors '''
    import urllib.request, urllib.error, urllib.parse
    try:
        print("Downloading: {0}".format(filename))
        geturl = '/'.join([baseurl, filename])
        if user is None:
            res = urllib.request.urlopen(geturl)
        else:
            mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, baseurl, user, password)
            handler = urllib.request.HTTPBasicAuthHandler(mgr)
            opener = urllib.request.build_opener(handler)
            res = opener.open(geturl)
        return res.fp
    except urllib.error.URLError as e:
        logger.warning(e.reason + ': {0}'.format(geturl))
        return None


def hash_stream(blockiter, outstream):
    '''
    Writes blockiter to outstream and returns the digest and bytes written
    '''
    hasher = hashlib.new('sha1')
    bytes_written = 0

    for block in blockiter:
        # Add the block to be hashed
        hasher.update(block)
        bytes_written += len(block)
        outstream.write(block)
    outstream.flush()
    return hasher.hexdigest(), bytes_written


class BackendInterface(object):
    """ __init__ and pull_files are required, push_files is optional """

    def __init__(self, base_dir, **kwargs):
        """ Configuration options should be set in here """
        raise NotImplementedError(NOT_IMPLEMENTED_MESSAGE)

    def push_files(self, file_list):
        """ Return True if push was successful, False otherwise. Not required but useful """
        raise NotImplementedError(NOT_IMPLEMENTED_MESSAGE)

    def pull_files(self, file_list):
        """ Return True if pull was successful, False otherwise """
        raise NotImplementedError(NOT_IMPLEMENTED_MESSAGE)


class CopyBackend(BackendInterface):
    def __init__(self, base_dir, **kwargs):
        other_path = kwargs.get('remote')
        if not os.path.isdir(other_path):
            raise RuntimeError('copybackend target path is not directory: {}'.format(other_path))
        logger.debug("CopyBackend: other_path={}, base_dir={}"
                     .format(other_path, base_dir))
        self.other_path = other_path
        self.base_dir = base_dir

    def pull_files(self, file_list):
        for f in file_list:
            fullpath = os.path.join(self.other_path, f)
            shutil.copy2(fullpath, self.base_dir)
        return True

    def push_files(self, file_list):
        for f in file_list:
            fullpath = os.path.join(self.base_dir, f)
            shutil.copy2(fullpath, self.other_path)
        return True


class HTTPBackend(BackendInterface):
    """ Pull files from an HTTP server """

    def __init__(self, base_dir, **kwargs):
        remote_url = kwargs.get('remote')
        if not remote_url:
            raise RuntimeError('No remote url configured for http backend')

        if not (remote_url.startswith('http') or remote_url.startswith('https')):
            raise RuntimeError('http remote url must start with http:// or https://')

        self.remote_url = remote_url
        self.user = kwargs.get('user')
        self.password = kwargs.get('password')
        self.base_dir = base_dir

    def pull_files(self, file_list):
        is_success = True

        for o in file_list:
            stream = http_get(self.remote_url, o, self.user, self.password)
            blockiter = readblocks(stream)

            # HTTP Error
            if blockiter is None:
                is_success = False
                continue

            fd, tmpname = tempfile.mkstemp(dir=self.base_dir)
            with os.fdopen(fd, 'wb') as tmpstream:
                # Hash the input, write to temp file
                digest, _ = hash_stream(blockiter, tmpstream)

            if digest != o:
                # Should I retry?
                logger.error(
                    'Downloaded digest ({0}) did not match stored digest for orphan: {1}'.format(digest, o))
                delete_file(tmpname)
                is_success = False
                continue

            objfile = os.path.join(self.base_dir, digest)
            os.chmod(tmpname, int('444', 8) & ~umask())
            # Rename temp file.
            move_file(tmpname, objfile)

        return is_success


class RSyncBackend(BackendInterface):
    """ Push and pull files from rsync remote """

    def __init__(self, base_dir, **kwargs):
        remote_url = kwargs.get('remote')

        # Allow support for rsyncd servers (Looks like "remote = example.org::mybins")
        ssh_user = ''
        ssh_port = ''
        if "::" in remote_url:
            self.is_rsyncd_remote = True
        else:
            self.is_rsyncd_remote = False
            ssh_user = kwargs.get('sshuser')
            ssh_port = kwargs.get('sshport', '22')

        if not remote_url:
            raise RuntimeError("No remote url configured for rsync")

        self.remote_url = remote_url
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port
        self.base_dir = base_dir
        # Swap Windows style drive letters (e.g. 't:') for cygwin style drive letters (e.g. '/t')
        # Otherwise, when using an rsyncd remote (e.g. 'example.org::bin'),
        # The rsync client on Windows will exit with this error:
        # "The source and destination cannot both be remote."
        # Presumably, this is because rsync assumes any path is remote if it contains a colon.
        if platform.system() == 'Windows' and self.is_rsyncd_remote and self.base_dir.find(':') == 1:
            self.base_dir = "/" + self.base_dir[0] + self.base_dir[2:]

    def _rsync(self, push):
        ''' Construct the rsync command '''
        if platform.system() == 'Windows':
            # Windows installer ships its own rsync tool
            rsync_tool = 'git-fat_rsync.exe'
        else:
            rsync_tool = 'rsync'
        cmd_tmpl = [rsync_tool] + ' --protect-args --progress'\
            ' --ignore-existing --from0 --files-from=-'.split()

        if push:
            src, dst = self.base_dir, self.remote_url
        else:
            src, dst = self.remote_url, self.base_dir
        cmd = cmd_tmpl + [src + '/', dst + '/']

        # extra must be passed in as single argv, which is why it's
        # not in the template and split isn't called on it
        if self.is_rsyncd_remote:
            extra = ''
        elif GIT_SSH:
            extra = '--rsh={}'.format(GIT_SSH)
        elif platform.system() == "Windows":
            extra = '--rsh=git-fat_ssh.exe'
        else:
            extra = '--rsh=ssh'

        if self.ssh_user:
            extra = ' '.join([extra, '-l {}'.format(self.ssh_user)])
        if self.ssh_port:
            extra = ' '.join([extra, '-p {}'.format(self.ssh_port)])

        if extra:
            cmd.append(extra)

        return cmd

    def pull_files(self, file_list):
        rsync = self._rsync(push=False)
        logger.debug("rsync pull command: {}".format(" ".join(rsync)))
        try:
            p = subprocess.Popen(rsync, stdin=subprocess.PIPE)
        except OSError:
            # re-raise with a more useful message
            raise OSError('Error running "%s"' % " ".join(rsync))

        p.communicate(input='\x00'.join(file_list))
        # TODO: fix for success check
        return True

    def push_files(self, file_list):
        rsync = self._rsync(push=True)
        logger.debug("rsync push command: {}".format(" ".join(rsync)))
        p = subprocess.Popen(rsync, stdin=subprocess.PIPE)
        p.communicate(input='\x00'.join(file_list))
        # TODO: fix for success check
        return True


class AWS_S3Backend(BackendInterface):

    AWS_AUTH_FILE = "~/.aws/credentials"
    AWS_AUTH_FILE_DEFAULT_CONFIG = "default"
    AWS_ACCESS_KEY = "aws_access_key_id"
    AWS_ACCESS_SECRET_KEY = "aws_secret_access_key"
    GITFAT_CONFIG_FILE_REGION_NAME_KEY = "region_name"
    GITFAT_CONFIG_FILE_BUCKET_KEY = "bucket"
    GITFAT_CONFIG_FILE_OBJECT_FOLDER = "object_folder"
    GITFAT_CONFIG_AUTH_FILE_KEY = "credentials_file"
    GITFAT_CONFIG_AUTH_FILE_SECTION_KEY = "credentials_file_section"
    GITFAT_DOWNLOAD_THREAD_NUM = 8
    GITFAT_CONFIG_PREFIX = 'file_name_prefix'
    DEFAULT_FILE_NAME_PREFIX = "gitfat-"

    class ThreadedTransfer(threading.Thread):

        def __init__(self, aws_client, bucket, file_path, opt_folder='', file_prefix='gitfat-', direction="up"):
            super(AWS_S3Backend.ThreadedTransfer, self).__init__()
            self.client = aws_client
            self.bucket = bucket
            self.file_name = os.path.basename(file_path)
            self.opt_folder = opt_folder if opt_folder else ''
            self.file_path = file_path
            self.direction = direction
            self.success = True
            self.err_msg = None
            self.file_name_prefix = file_prefix

        def download(self):
            with open(self.file_path, "wb") as self.downloaded_file_fd:
                git_fat_obj_loc = os.path.join(self.opt_folder,
                                               "%s%s" % (self.file_name_prefix, self.file_name))
                print("object loc", git_fat_obj_loc)
                try:
                    self.client.download_fileobj(self.bucket, git_fat_obj_loc,
                                                 self.downloaded_file_fd)
                    os.chmod(self.file_path, int('444', 8) & ~umask())
                except botocore.exceptions.ClientError as e:
                    if os.path.exists(self.file_path) and os.path.getsize(self.file_path) == 0:
                        os.unlink(self.file_path)
                    self.success = False
                    self.err_msg = "Warning: Could not download file %s from remote\nWarning: Remote response: %s" % (
                        self.file_name, str(e))

        def upload(self):
            git_fat_obj_loc = os.path.join(self.opt_folder,
                                           "%s%s" % (self.file_name_prefix, self.file_name))
            obj_b = self.client.list_objects_v2(Bucket=self.bucket, Prefix=git_fat_obj_loc)
            if "Contents" in obj_b:
                self.success = False
                self.err_msg = 'object already exists in fatstore: %s' % git_fat_obj_loc
                return
            if self.success:
                with open(self.file_path, "r") as file_content_fd:
                    print("uploading", git_fat_obj_loc)
                    self.client.upload_fileobj(file_content_fd, self.bucket, git_fat_obj_loc)

        def run(self):
            if self.direction == "up":
                self.upload()
            elif self.direction == "down":
                self.download()
            else:
                self.success = False
                self.err_msg = "Programming error"

    def get_region_name(self, kwargs):
        region_name = self.kwargs.get(AWS_S3Backend.GITFAT_CONFIG_FILE_REGION_NAME_KEY, None)
        if region_name is None:
            raise RuntimeError("Your .gitfat [%s] config does not contain any '%s' key." % (
                AWS_S3Backend.AWS_ACCESS_KEY, AWS_S3Backend.GITFAT_CONFIG_FILE_REGION_NAME_KEY))
        if len(region_name) == 0:
            raise RuntimeError("Your .gitfat [%s] config does not contain any value for "
                               "the '%s' key: '%s'" % (
                                   AWS_S3Backend.AWS_ACCESS_KEY,
                                   AWS_S3Backend.GITFAT_CONFIG_FILE_REGION_NAME_KEY, region_name))
        return region_name

    def get_transfer_threads_number(self, kwargs):
        try:
            transfer_num_threads = int(self.kwargs.get(
                "transfer_num_threads", AWS_S3Backend.GITFAT_DOWNLOAD_THREAD_NUM))
            if transfer_num_threads <= 0:
                raise ValueError("The transfer_num_threads value must be a positive integer")
            return transfer_num_threads
        except ValueError as e:
            raise RuntimeError("transfer_num_threads: Bad value: %s" % str(e))

    def get_valid_s3_bucket_name(self, kwargs):
        bucket_name = kwargs.get(AWS_S3Backend.GITFAT_CONFIG_FILE_BUCKET_KEY, None)
        if bucket_name is None:
            raise RuntimeError("Your .gitfat [%s] config does not contain any '%s' key." % (
                AWS_S3Backend.AWS_ACCESS_KEY, AWS_S3Backend.GITFAT_CONFIG_FILE_BUCKET_KEY))
        if len(bucket_name) == 0:
            raise RuntimeError("Your .gitfat [%s] config does not contain any value for '%s' key." % (
                AWS_S3Backend.AWS_ACCESS_KEY, AWS_S3Backend.GITFAT_CONFIG_FILE_BUCKET_KEY))
        try:

            if not (bucket_name in [bucket.name for bucket in self.aws_s3_resource.buckets.all()]):
                raise RuntimeError(
                    "Your .gitfat [%s] specified bucket does not exist in AWS S3" %
                    AWS_S3Backend.BACKEND_KEY)
        except botocore.exceptions.EndpointConnectionError as e:
            raise RuntimeError(
                "Your .gitfat config contains an invalid region_name key value: %s" % str(e))
        except botocore.exceptions.ClientError as e:
            if "InvalidAccessKeyId" in str(e):
                raise RuntimeError(
                    "You seem not to have an valid AWS S3 access key setup: %s" % str(e))
            if "SignatureDoesNotMatch" in str(e):
                raise RuntimeError(
                    "You seem not to have a valid AWS S3 secret key setup: %s" % str(e))
            if "RequestTimeTooSkewed" in str(e):
                raise RuntimeError(
                    "Your system may not have proper date or time setup: %s" % str(e))
        return bucket_name

    def __init__(self, base_dir, **kwargs):
        import boto3
        self.base_dir = base_dir
        self.kwargs = kwargs
        self.region_name = self.get_region_name(kwargs)
        self.transfer_num_threads = self.get_transfer_threads_number(kwargs)
        self.access_key, self.access_secret = self.get_credentials(kwargs)
        if self.access_key is None and 'AWS_SESSION_TOKEN' in os.environ:
            # this assumes these 3 are set and you want to use them
            self.aws_s3_session = boto3.Session(
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN', None),
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID', None),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY', None),
                region_name=self.region_name)
        else:
            self.aws_s3_session = boto3.Session(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.access_secret,
                region_name=self.region_name)
        self.aws_s3_resource = self.aws_s3_session.resource("s3")
        self.aws_s3_client = self.aws_s3_resource.meta.client
        self.bucket_name = self.get_valid_s3_bucket_name(kwargs)
        self.s3_object_folder = self.get_object_folder_name()
        self.file_name_prefix = self.get_filename_prefix()

    def get_filename_prefix(self):
        ff = self.kwargs.get(AWS_S3Backend.GITFAT_CONFIG_PREFIX, None)
        if ff is None:
            return self.DEFAULT_FILE_NAME_PREFIX
        else:
            return ff

    def get_object_folder_name(self):
        ff = self.kwargs.get(AWS_S3Backend.GITFAT_CONFIG_FILE_OBJECT_FOLDER, "")
        return ff

    @property
    def has_credentials_file(self):
        return AWS_S3Backend.GITFAT_CONFIG_AUTH_FILE_KEY in self.kwargs

    @property
    def has_direct_credentials(self):
        return (AWS_S3Backend.AWS_ACCESS_KEY in self.kwargs and
                AWS_S3Backend.AWS_ACCESS_SECRET_KEY in self.kwargs)

    def get_credentials(self, kwargs):
        try:
            if self.has_credentials_file:
                cc = self.read_credentials_from_file(
                    self.kwargs.get(AWS_S3Backend.GITFAT_CONFIG_AUTH_FILE_KEY),
                    self.kwargs.get(AWS_S3Backend.GITFAT_CONFIG_AUTH_FILE_SECTION_KEY,
                                    AWS_S3Backend.AWS_AUTH_FILE_DEFAULT_CONFIG))
                if cc == ('None', 'None'):
                    return None, None
                return cc
            elif self.has_direct_credentials:
                return (self.kwargs[AWS_S3Backend.AWS_ACCESS_KEY],
                        self.kwargs[AWS_S3Backend.AWS_ACCESS_SECRET_KEY])
            else:
                return self.read_credentials_from_file(
                    os.path.expanduser(AWS_S3Backend.AWS_AUTH_FILE),
                    AWS_S3Backend.AWS_AUTH_FILE_DEFAULT_CONFIG)
        except RuntimeError as e:
            if self.has_env_credentials:
                logger.info('Using environment Creds')
                return None, None
            else:
                raise RuntimeError("Credentials improperly configured (%s)" % str(e))

    @property
    def has_env_credentials(self):
        return ("AWS_SECRET_ACCESS_KEY" in os.environ
                and "AWS_ACCESS_KEY_ID" in os.environ) or ("AWS_PROFILE" in os.environ)


    def read_credentials_from_file(self, file_path, section):
        if not os.path.exists(file_path):
            raise RuntimeError("AWS authentication file '%s' not found" % file_path)
        parser = configparser.ConfigParser()
        parser.read(file_path)
        try:
            return (parser.get(section, AWS_S3Backend.AWS_ACCESS_KEY),
                    parser.get(section, AWS_S3Backend.AWS_ACCESS_SECRET_KEY))
        except configparser.NoSectionError:
            raise RuntimeError(
                "AWS authentication file '%s' does not have section '%s'" % (file_path, section))
        except configparser.NoOptionError:
            raise RuntimeError("AWS authentication file section '%s' does not have proper "
                "keys setup (%s, and %s)" % (file_path,
                AWS_S3Backend.AWS_ACCESS_KEY,
                AWS_S3Backend.AWS_ACCESS_SECRET_KEY), section)

    def generic_transfer(self, file_list, direction="up"):
        def get_transfer_direction_str(direction):
            if direction == "up":
                return "upload"
            elif direction == "down":
                return "download"
            else:
                raise Exception("Programming Error")
        num_slots_avail = self.transfer_num_threads
        next_file_idx_to_download = 0
        threads = {}
        processed_file = 1
        num_files = len(file_list)
        while True:
            if num_slots_avail and next_file_idx_to_download < num_files:
                file_to_download = file_list[next_file_idx_to_download]
                next_file_idx_to_download += 1
                num_slots_avail -= 1
                downloader = AWS_S3Backend.ThreadedTransfer(
                    self.aws_s3_client,
                    self.bucket_name,
                    file_to_download,
                    opt_folder=self.s3_object_folder,
                    file_prefix=self.file_name_prefix,
                    direction=direction)
                threads[id(downloader)] = downloader
                downloader.start()
            else:
                if next_file_idx_to_download >= num_files and len(threads) == 0:
                    break
                for thread in list(threads.values()):
                    if thread.is_alive():
                        continue
                    else:
                        if thread.success:
                            file_size = os.path.getsize(thread.file_path)
                            if file_size < 1024:
                                file_size_human_readable = "%dB" % file_size
                            else:
                                file_size_human_readable = "%d.%dKB" % (
                                    file_size / 1024, file_size % 1024)
                            print("%sed %d/%d %s ... %s" % (get_transfer_direction_str(direction).title(),
                                                            processed_file, num_files, thread.file_name, file_size_human_readable))
                        else:
                            print(thread.err_msg)
                        processed_file += 1
                        thread = threads[id(thread)]
                        del threads[id(thread)]
                        del thread
                        num_slots_avail += 1

    def push_files(self, file_list):
        def retrieve_s3_stored_objects_ids(self):
            print("Retrieving remote file list ...")
            bucket = self.aws_s3_resource.Bucket(self.bucket_name)
            ff = self.file_name_prefix
            if self.s3_object_folder:
                prefx = "%s/%s" % (self.s3_object_folder, self.file_name_prefix)
            else:
                prefx = self.file_name_prefix
            return [obj.key.split('-')[-1] for obj in bucket.objects.filter(Prefix=prefx)]
        file_ids = retrieve_s3_stored_objects_ids(self)
        files_to_upload = [os.path.join(self.base_dir, file_path)
                           for file_path in list(set(file_list) - set(file_ids))]
        num_files = len(files_to_upload)
        if num_files == 0:
            print("No files to upload ...")
            return False
        print("Uploading %d files ..." % num_files)
        self.generic_transfer(files_to_upload, "up")
        return True

    def pull_files(self, file_list):
        file_list = [os.path.join(self.base_dir, file_name) for file_name in list(file_list)]
        num_files = len(file_list)
        if num_files == 0:
            print("No files to download ...")
            return False
        print("Downloading %d files ..." % num_files)
        self.generic_transfer(file_list, "down")
        return True


BACKEND_MAP = {
    'rsync': RSyncBackend,
    'http': HTTPBackend,
    'copy': CopyBackend,
    'aws-s3': AWS_S3Backend
}


class GitFat(object):

    def __init__(self, backend, full_history=False):

        # The backend instance we use to get the files
        self.backend = backend
        self.full_history = full_history
        self.rev = None  # Unused
        self.objdir = _obj_dir()
        # Cookie is used mostly in bytes operations, so store it as bytes
        self._cookie = b'#$# git-fat '
        self._format = '{cookie}{digest} {size:20d}\n'

        # Legacy format support below, need to actually check the version once/if we have more than 2
        if os.environ.get('GIT_FAT_VERSION'):
            self._format = '{cookie}{digest}\n'

        # considers the git-fat version when generating the magic length
        def _ml(fn): return len(fn(hashlib.sha1(b'dummy').hexdigest(), 5))
        self._magiclen = _ml(self._get_placeholder)

        self.configure()

    def configure(self):
        '''
        Configure git-fat for usage: variables, environment
        '''
        if not self._configured():
            print('Setting filters in .git/config')
            gitconfig_set('filter.fat.clean', 'git-fat filter-clean %f')
            gitconfig_set('filter.fat.smudge', 'git-fat filter-smudge %f')
            print('Creating .git/fat/objects')
            mkdir_p(self.objdir)
            print('Initialized git-fat')

    def _configured(self):
        '''
        Returns true if git-fat is already configured
        '''
        reqs = os.path.isdir(self.objdir)
        filters = gitconfig_get('filter.fat.clean') and gitconfig_get('filter.fat.smudge')
        return filters and reqs

    def _get_placeholder(self, digest, size):
        '''
        Produce str repr of file to be stored in repo.
        '''
        # 20 chars can hold 64-bit integers.
        return self._format.format(cookie=self._cookie, digest=digest, size=size)

    def _decode(self, stream):
        '''
        Returns iterator and True if stream is git-fat object
        '''
        stream_iter = readblocks(stream)
        # Read block for check raises StopIteration if file is zero length
        try:
            block = next(stream_iter)
        except StopIteration:
            return stream_iter, False

        def prepend(blk, iterator):
            yield blk
            for i in iterator:
                yield i

        # Put block back
        ret = prepend(block, stream_iter)
        if block.startswith(self._cookie):
            if len(block) != self._magiclen:  # Sanity check
                warnings.warn('Found file with cookie but without magiclen')
                return ret, False
            return ret, True
        return ret, False

    def _get_digest(self, stream):
        '''
        Returns digest if stream is fatfile placeholder or None if not
        '''
        # DONT EVER CALL THIS FUNCTION FROM FILTERS, IT DISCARDS THE FIRST
        # BLOCK OF THE INPUT STREAM.  IT IS ONLY MEANT TO CHECK THE STATUS
        # OF A FILE IN THE TREE
        stream, fatfile = self._decode(stream)
        if fatfile:
            block = next(stream)  # read the first block
            digest = block.split()[2]
            return digest
        return None

    def _cached_objects(self):
        '''
        Returns a set of all the cached objects
        '''
        return set(os.listdir(self.objdir))

    def _referenced_objects(self, **kwargs):
        '''
        Return just the hashes of the files that are referenced in the repository
        '''
        objs_dict = self._managed_files(**kwargs)
        return set(objs_dict.keys())

    def _rev_list(self):
        '''
        Generator for objects in rev. Returns (hash, type, size) tuple.
        '''

        rev = self.rev or 'HEAD'
        # full_history implies --all
        args = ['--all'] if self.full_history else ['--no-walk', rev]

        # Get all the git objects in the current revision and in history if --all is specified
        revlist = git('rev-list --objects'.split() + args, stdout=subprocess.PIPE)
        # Grab only the first column.  Tried doing this in python but because of the way that
        # subprocess.PIPE buffering works, I was running into memory issues with larger repositories
        # plugging pipes to other subprocesses appears to not have the memory buffer issue
        if platform.system() == "Windows":
            # Windows installer ships its own awk tool
            awk_tool = 'git-fat_gawk.exe'
        else:
            awk_tool = 'awk'
        awk = subprocess.Popen([awk_tool, '{print $1}'], stdin=revlist.stdout, stdout=subprocess.PIPE)
        # Read the objects and print <sha> <type> <size>
        catfile = git('cat-file --batch-check'.split(), stdin=awk.stdout, stdout=subprocess.PIPE)

        for line in catfile.stdout:
            objhash, objtype, size = line.split()
            yield objhash, objtype, size

        catfile.wait()

    def _find_paths(self, hashes):
        '''
        Takes a list of git object hashes and generates hash,path tuples
        '''
        rev = self.rev or 'HEAD'
        # full_history implies --all
        args = ['--all'] if self.full_history else ['--no-walk', rev]

        revlist = git('rev-list --objects'.split() + args, stdout=sub.PIPE)
        for line in revlist.stdout:
            hashobj = line.strip()
            # Revlist prints all objects (commits, trees, blobs) but blobs have the file path
            # next to the git objecthash
            # Handle files with spaces
            hashobj, _, filename = hashobj.partition(' ')
            if filename:
                # If the object is one we're managing
                if hashobj in hashes:
                    yield hashobj, filename

        revlist.wait()

    def _managed_files(self, **unused_kwargs):
        revlistgen = self._rev_list()
        # Find any objects that are git-fat placeholders which are tracked in the repository
        managed = {}
        for objhash, objtype, size in revlistgen:
            # files are of blob type
            if objtype == 'blob' and int(size) == self._magiclen:
                # Read the actual file contents
                readfile = git(['cat-file', '-p', objhash], stdout=subprocess.PIPE)
                digest = self._get_digest(readfile.stdout)
                if digest:
                    managed[objhash] = digest

        # go through rev-list again to get the filenames
        # Again, I tried avoiding making another call to rev-list by caching the
        # filenames above, but was running into the memory buffer issue
        # Instead we just make another call to rev-list.  Takes more time, but still
        # only takes 5 seconds to traverse the entire history of a 22k commit repo
        filedict = dict(self._find_paths(list(managed.keys())))

        # return a dict(git-fat hash -> filename)
        # git's objhash are the keys in `managed` and `filedict`
        ret = dict((j, filedict[i]) for i, j in managed.iteritems())
        return ret

    def _orphan_files(self, patterns=None):
        '''
        generator for placeholders in working tree that match pattern
        '''
        patterns = patterns or []
        # Null-terminated for proper file name handling (spaces)
        # Drops the final, empty string, result
        for fname in debug_check_output(['git', 'ls-files', '-z'] + patterns, text=True).split('\x00')[:-1]:
            if not os.path.exists(fname):
                continue
            st = os.lstat(fname)
            if st.st_size != self._magiclen or os.path.islink(fname):
                continue
            with open(fname, "rb") as f:
                digest = self._get_digest(f)
            if digest:
                yield (digest, fname)

    def _filter_smudge(self, instream, outstream):
        '''
        The smudge filter runs whenever a file is being checked out into the working copy of the tree
        instream is sys.stdin and outstream is sys.stdout when it is called by git
        '''
        blockiter, fatfile = self._decode(instream)
        if fatfile:
            block = next(blockiter)  # read the first block
            digest = block.split()[2]
            objfile = os.path.join(self.objdir, digest)
            try:
                with open(objfile, "rb") as f:
                    cat(f, outstream)
                logger.info('git-fat filter-smudge: restoring from {}'.format(objfile))
            except IOError:
                logger.info('git-fat filter-smudge: fat object not found in cache {}'.format(objfile))
                outstream.write(block)
        else:
            logger.info('git-fat filter-smudge: not a managed file')
            cat_iter(blockiter, sys.stdout)

    def _filter_clean(self, instream, outstream):
        '''
        The clean filter runs when a file is added to the index. It gets the "smudged" (working copy)
        version of the file on stdin and produces the "clean" (repository) version on stdout.
        '''

        blockiter, is_placeholder = self._decode(instream)

        if is_placeholder:
            # This must be cat_iter, not cat because we already read from instream
            cat_iter(blockiter, outstream)
            return

        # make temporary file for writing
        fd, tmpname = tempfile.mkstemp(dir=self.objdir)
        tmpstream = os.fdopen(fd, 'wb')

        # Hash the input, write to temp file
        digest, size = hash_stream(blockiter, tmpstream)
        tmpstream.close()

        objfile = os.path.join(self.objdir, digest)

        if os.path.exists(objfile):
            logger.info('git-fat filter-clean: cached file already exists {}'.format(objfile))
            # Remove temp file
            delete_file(tmpname)
        else:
            # Set permissions for the new file using the current umask
            os.chmod(tmpname, int('444', 8) & ~umask())
            # Rename temp file
            move_file(tmpname, objfile)
            logger.info('git-fat filter-clean: caching to {}'.format(objfile))

        # Write placeholder to index
        # outstream is a binary buffer, so encode string to UTF-8 bytes
        outstream.write(self._get_placeholder(digest, size).encode('UTF-8'))

    def filter_clean(self, cur_file, **unused_kwargs):
        '''
        Public command to do the clean (should only be called by git)
        '''
        logger.debug("CLEAN: cur_file={}, unused_kwargs={}"
                     .format(cur_file, unused_kwargs))
        if cur_file and not self.can_clean_file(cur_file):
            logger.info(
                "Not adding: {0}. ".format(cur_file) +
                "It is not a new file and is not managed by git-fat"
            )
            # Git needs something, so we cat stdin to stdout
            cat(sys.stdin, sys.stdout)
        else:  # We clean the file
            if cur_file:
                logger.info("Adding {0}".format(cur_file))
            self._filter_clean(sys.stdin, sys.stdout)

    def filter_smudge(self, **unused_kwargs):
        '''
        Public command to do the smudge (should only be called by git)
        '''
        logger.debug("SMUDGE: unused_kwargs={}".format(unused_kwargs))
        self._filter_smudge(sys.stdin, sys.stdout)

    def find(self, size, **unused_kwargs):
        '''
        Find any files over size threshold in the repository.
        '''
        revlistgen = self._rev_list()
        # Find any objects that are git-fat placeholders which are tracked in the repository
        objsizedict = {}
        for objhash, objtype, objsize in revlistgen:
            # files are of blob type
            if objtype == 'blob' and int(objsize) > size:
                objsizedict[objhash] = objsize
        for objhash, objpath in self._find_paths(list(objsizedict.keys())):
            print(objhash, objsizedict[objhash], objpath)

    def _parse_ls_files(self, line):
        mode, _, tail = line.partition(' ')
        blobhash, _, tail = tail.partition(' ')
        stageno, _, tail = tail.partition('\t')
        filename = tail.strip()
        return mode, blobhash, stageno, filename

    def _get_old_gitattributes(self):
        """ Get the last .gitattributes file in HEAD, and return it """
        ls_ga = git('ls-files -s .gitattributes'.split(), stdout=subprocess.PIPE)
        lsout = ls_ga.stdout.read().strip()
        ls_ga.wait()
        if lsout:  # Always try to get the old gitattributes
            ga_mode, ga_hash, ga_stno, _ = self._parse_ls_files(lsout)
            ga_cat = git('cat-file blob {0}'.format(ga_hash).split(), stdout=subprocess.PIPE)
            old_ga = ga_cat.stdout.read().splitlines()
            ga_cat.wait()
        else:
            ga_mode, ga_stno, old_ga = '100644', '0', []
        return old_ga, ga_mode, ga_stno

    def _update_index(self, uip, mode, content, stageno, filename):
        fmt = '{0} {1} {2}\t{3}\n'
        uip.stdin.write(fmt.format(mode, content, stageno, filename))

    def _add_gitattributes(self, newfiles, unused_update_index):
        """ Find the previous gitattributes file, and append to it """

        old_ga, ga_mode, ga_stno = self._get_old_gitattributes()
        ga_hashobj = git('hash-object -w --stdin'.split(), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
        # Add lines to the .gitattributes file
        new_ga = old_ga + ['{0} filter=fat -text'.format(f) for f in newfiles]
        stdout, _ = ga_hashobj.communicate('\n'.join(new_ga) + '\n')
        return ga_mode, stdout.strip(), ga_stno, '.gitattributes'

    def _process_index_filter_line(self, line, workdir, excludes):

        mode, blobhash, stageno, filename = self._parse_ls_files(line)

        if filename not in excludes or mode == "120000":
            return None
        # Save file to update .gitattributes
        cleanedobj_hash = os.path.join(workdir, blobhash)
        # if it hasn't already been cleaned
        if not os.path.exists(cleanedobj_hash):
            catfile = git('cat-file blob {}'.format(blobhash).split(), stdout=subprocess.PIPE)
            hashobj = git('hash-object -w --stdin'.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self._filter_clean(catfile.stdout, hashobj.stdin)
            hashobj.stdin.close()
            objhash = hashobj.stdout.read().strip()
            catfile.wait()
            hashobj.wait()
            with open(cleanedobj_hash, 'wb') as cleaned:
                cleaned.write(objhash + '\n')
        else:
            with open(cleanedobj_hash, 'rb') as cleaned:
                objhash = cleaned.read().strip()
        return mode, objhash, stageno, filename

    def index_filter(self, filelist, add_gitattributes=True, **unused_kwargs):
        gitdir = debug_check_output('git rev-parse --git-dir'.split(), text=True).strip()
        workdir = os.path.join(gitdir, 'fat', 'index-filter')
        mkdir_p(workdir)

        with open(filelist, 'rb') as excludes:
            files_to_exclude = excludes.read().splitlines()

        ls_files = git('ls-files -s'.split(), stdout=subprocess.PIPE)
        uip = git('update-index --index-info'.split(), stdin=subprocess.PIPE)

        newfiles = []
        for line in ls_files.stdout:
            newfile = self._process_index_filter_line(line, workdir, files_to_exclude)
            if newfile:
                self._update_index(uip, *newfile)
                # The filename is in the last position
                newfiles.append(newfile[-1])

        if add_gitattributes:
            # Add the files to the gitattributes file and update the index
            attrs = self._add_gitattributes(newfiles, add_gitattributes)
            self._update_index(uip, *attrs)

        ls_files.wait()
        uip.stdin.close()
        uip.wait()

    def list_files(self, **kwargs):
        '''
        Command to list the files by fat-digest -> gitroot relative path
        '''
        managed = self._managed_files(**kwargs)
        for f in list(managed.keys()):
            print(f, managed.get(f))

    def _remove_orphan_file(self, fname):
        # The output of our smudge filter depends on the existence of
        # the file in .git/fat/objects, but git caches the file stat
        # from the previous time the file was smudged, therefore it
        # won't try to re-smudge. There's no git command to specifically
        # invalidate the index cache so we have two options:
        # Change the file stat mtime or change the file size. However, since
        # the file mtime only has a granularity of 1s, if we're doing a pull
        # right after a clone or checkout, it's possible that the modified
        # time will be the same as in the index. Git knows this can happen
        # so git checks the file size if the modified time is the same.
        # The easiest way around this is just to remove the file we want
        # to replace (since it's an orphan, it should be a placeholder)
        with open(fname, 'rb') as f:
            recheck_digest = self._get_digest(f)  # One last sanity check
        if recheck_digest:
            delete_file(fname)

    def checkout(self, show_orphans=False, **unused_kwargs):
        '''
        Update any stale files in the present working tree
        '''
        to_checkout = []
        for digest, fname in self._orphan_files():
            objpath = os.path.join(self.objdir, digest)
            if os.access(objpath, os.R_OK):
                print('Restoring %s -> %s' % (digest, fname))
                self._remove_orphan_file(fname)
                # This re-smudge is essentially a copy that restores permissions.
                to_checkout.append(fname)
            elif show_orphans:
                print('Data unavailable: %s %s' % (digest, fname))
        subprocess.check_call(['git', 'checkout-index', '--index', '--force'] + to_checkout)

    def can_clean_file(self, filename):
        '''
        Checks to see if the current file exists in the local repo before filter-clean
        This method prevents fat from hijacking glob matches that are old
        '''
        # If the file doesn't exist in the immediately previous revision, add it
        showfile = git(['show', 'HEAD:{0}'.format(filename)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        blockiter, is_fatfile = self._decode(showfile.stdout)

        # Flush the buffers to prevent deadlock from wait()
        # Caused when stdout from showfile is a large binary file and can't be fully buffered
        # I haven't figured out a way to avoid this unfortunately
        for _ in blockiter:
            continue

        if showfile.wait() or is_fatfile:
            # The file didn't exist in the repository
            # The file was a fatfile (which may have changed)
            return True

        # File exists but is not a fatfile, don't add it
        return False

    def pull(self, patterns=None, **kwargs):
        """ Get orphans, call backend pull """
        cached_objs = self._cached_objects()

        # TODO: Why use _orphan _and_ _referenced here?
        if patterns:
            # filter the working tree by a pattern
            files = set(digest for digest, fname in self._orphan_files(
                patterns=patterns)) - cached_objs
        else:
            # default pull any object referenced but not stored
            files = self._referenced_objects(**kwargs) - cached_objs

        logger.debug("PULL: patterns={}, kwargs={}, len(files)={}"
                     .format(patterns, kwargs, len(files)))

        if not self.backend.pull_files(files):
            sys.exit(1)
        self.checkout()

    def push(self, unused_pattern=None, **kwargs):
        # We only want the intersection of the referenced files and ones we have cached
        # Prevents file doesn't exist errors, while saving on bw by default (_referenced only
        # checks HEAD for files)
        files = self._referenced_objects(**kwargs) & self._cached_objects()
        logger.debug("PUSH: unused_pattern={}, kwargs={}, len(files)={}"
                     .format(unused_pattern, kwargs, len(files)))
        if not self.backend.push_files(files):
            sys.exit(1)

    def _status(self, **kwargs):
        '''
        Helper function that returns the oprhans and stale files
        '''
        catalog = self._cached_objects()
        referenced = self._referenced_objects(**kwargs)
        stale = catalog - referenced
        orphans = referenced - catalog
        return stale, orphans

    def status(self, **kwargs):
        '''
        Show orphan (in tree, but not in cache) and stale (in cache, but not in tree) objects, if any.
        '''
        stale, orphans = self._status(**kwargs)
        if orphans:
            print('Orphan objects:')
            for orph in orphans:
                print('\t' + orph)
        if stale:
            print('Stale objects:')
            for g in stale:
                print('\t' + g)


def _get_options(config, backend, cfg_file_path):
    """ returns the options for a backend in dictionary form """
    try:
        opts = dict(config.items(backend))
    except configparser.NoSectionError:
        err = "No section found in {} for backend {}".format(cfg_file_path, backend)
        raise RuntimeError(err)
    return opts


def _read_config(cfg_file_path=None):
    config = configparser.ConfigParser()
    if not os.path.exists(cfg_file_path):
        # Can't continue, but this isn't unusual
        logger.warning("This does not appear to be a repository managed by git-fat. "
                       "Missing configfile at: {}".format(cfg_file_path))
        sys.exit(0)
    try:
        config.read(cfg_file_path)
    except configparser.Error:  # TODO: figure out what to catch here
        raise RuntimeError("Error reading or parsing configfile: {}".format(cfg_file_path))
    return config


def _parse_config(backend=None, cfg_file_path=None):
    """ Parse the given config file and return the backend instance """
    cfg_file_path = _config_path(path=cfg_file_path)
    config = _read_config(cfg_file_path)
    if backend is None:
        try:
            backends = config.sections()
        except configparser.Error:
            raise RuntimeError("Error reading or parsing configfile: {}".format(cfg_file_path))
        if not backends:  # e.g. empty file
            raise RuntimeError("No backends configured in config: {}".format(cfg_file_path))
        backend = backends[0]

    opts = _get_options(config, backend, cfg_file_path)
    base_dir = _obj_dir()

    try:
        Backend = BACKEND_MAP[backend]
    except IndexError:
        raise RuntimeError("Unknown backend specified: {}".format(backend))
    return Backend(base_dir, **opts)


def run(backend, **kwargs):
    make_sys_streams_binary()
    name = kwargs.pop('func')
    full_history = kwargs.pop('full_history')
    gitfat = GitFat(backend, full_history=full_history)
    fn = name.replace("-", "_")
    if not hasattr(gitfat, fn):
        raise Exception("Unknown function called")
    getattr(gitfat, fn)(**kwargs)


def _configure_logging(log_level):
    if GIT_FAT_LOG_LEVEL:
        log_level = GIT_FAT_LOG_LEVEL
    if GIT_FAT_LOG_FILE:
        file_handler = _logging.FileHandler(GIT_FAT_LOG_FILE)
        file_handler.setLevel(log_level)
        formatter = _logging.Formatter(
            '%(levelname)s:%(filename)s:%(funcName)s:%(lineno)d: %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    logger.setLevel(log_level)


def _load_backend(kwargs):
    needs_backend = ('pull', 'push')
    backend_opt = kwargs.pop('backend', None)
    config_file = kwargs.pop('config_file', None)
    backend = None
    if kwargs['func'] == 'pull':
        # since pull can be of the form pull [backend] [patterns], we need to check
        # the first argument and insert into file patterns if it's not a backend
        # this means you can't use a file pattern which is an exact match with
        # a backend name (e.g. you can't have a file named copy, rsync, http, etc)
        if backend_opt and backend_opt not in BACKEND_MAP:
            kwargs['patterns'].insert(0, backend_opt)
            backend_opt = None
    if kwargs['func'] in needs_backend:
        backend = _parse_config(backend=backend_opt, cfg_file_path=config_file)
    return backend


def main():

    parser = argparse.ArgumentParser(
        argument_default=argparse.SUPPRESS,
        description='A tool for managing large binary files in git repositories.')
    subparser = parser.add_subparsers()

    # Global options
    parser.add_argument(
        '-a', "--full-history", dest='full_history', action='store_true', default=False,
        help='Look for git-fat placeholder files in the entire history instead of just the working copy')
    parser.add_argument(
        '-v', "--verbose", dest='verbose', action='store_true',
        help='Get verbose output about what git-fat is doing')
    parser.add_argument(
        '-d', "--debug", dest='debug', action='store_true',
        help='Get debugging output about what git-fat is doing')
    parser.add_argument(
        '-c', "--config", dest='config_file', type=str,
        help='Specify which config file to use (defaults to .gitfat)')

    # redundant function for legacy api; config gets called every time.
    # (assuming if user is calling git-fat they want it configured)
    # plus people like running init when setting things up d(^_^)b
    sp = subparser.add_parser('init', help='Initialize git-fat')
    sp.set_defaults(func="configure")

    sp = subparser.add_parser('filter-clean', help="Internal function used by git")
    sp.add_argument("cur_file", nargs="?")
    sp.set_defaults(func='filter_clean')

    sp = subparser.add_parser('filter-smudge', help="Internal function used by git")
    sp.add_argument("cur_file", nargs="?")
    sp.set_defaults(func='filter_smudge')

    sp = subparser.add_parser('push', help='push cache to remote git-fat server')
    sp.add_argument("backend", nargs="?", help='pull using given backend')
    sp.set_defaults(func='push')

    sp = subparser.add_parser('pull', help='pull fatfiles from remote git-fat server')
    sp.add_argument("backend", nargs="?", help='pull using given backend')
    sp.add_argument("patterns", nargs="*", help='files or file patterns to pull')
    sp.set_defaults(func='pull')

    sp = subparser.add_parser('checkout', help='resmudge all orphan objects')
    sp.set_defaults(func='checkout')

    sp = subparser.add_parser('find', help='find all objects over [size]')
    sp.add_argument("size", type=int, help='threshold size in bytes')
    sp.set_defaults(func='find')

    sp = subparser.add_parser('status', help='print orphan and stale objects')
    sp.set_defaults(func='status')

    sp = subparser.add_parser('list', help='list all files managed by git-fat')
    sp.set_defaults(func='list_files')

    # Legacy function to preserve backwards compatability
    sp = subparser.add_parser('pull-http', help="Deprecated, use `pull http` (no dash) instead")
    sp.set_defaults(func='pull', backend='http')

    sp = subparser.add_parser('index-filter', help='git fat index-filter for filter-branch')
    sp.add_argument('filelist', help='file containing all files to import to git-fat')
    sp.add_argument(
        '-x', dest='add_gitattributes',
        help='prevent adding excluded to .gitattributes', action='store_false')
    sp.set_defaults(func='index_filter')

    if len(sys.argv) > 1 and sys.argv[1] in [c + 'version' for c in ['', '-', '--']]:
        print(__version__)
        sys.exit(0)

    args = parser.parse_args()
    kwargs = dict(vars(args))

    if kwargs.pop('debug', None):
        log_level = _logging.DEBUG
    elif kwargs.pop('verbose', None):
        log_level = _logging.INFO
    else:
        log_level = _logging.WARNING
    _configure_logging(log_level)

    try:
        backend = _load_backend(kwargs)  # load_backend mutates kwargs
        run(backend, **kwargs)
    except RuntimeError as err:
        logger.error(str(err))
        sys.exit(1)
    except:
        if kwargs.get('cur_file'):
            logger.error("processing file: " + kwargs.get('cur_file'))
        raise


if __name__ == '__main__':
    main()

__all__ = ['__version__', 'main', 'GitFat']
