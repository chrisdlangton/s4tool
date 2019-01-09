import os, shutil, boto3, multiprocessing, copy, hashlib, logging


class S3DownloadSync:
    def __init__(self, bucket_name, local_path, object_path=None):
        """
        :param bucket_name: str, the S3 bucket name
        :param local_path: str, a path to store the local files
        :param object_path: (optional, str) the object prefix for the sync
        """
        self.bucket_name = bucket_name
        self.object_path = object_path
        self.local_path = object_path

        os.makedirs(object_path)
        s3 = boto3.resource('s3')
        self.bucket = s3.Bucket(self.bucket_name)

    def __enter__(self):
        """Provides a context manager which will open but not sync, then delete the cache on exit"""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Provides a context manager which will open but not sync, then delete the cache on exit"""
        self.close()

    def __getstate__(self):
        # Require to pickle and un-pickle the self object between multiprocessing pools
        out = copy.copy(self.__dict__)
        out['bucket'] = None
        return out

    def __setstate__(self, d):
        # Require to pickle and un-pickle the self object between multiprocessing pools
        s3 = boto3.resource('s3')
        d['bucket'] = s3.Bucket(d['bucket_name'])
        self.__dict__ = d

    def get_path(self, key):
        """Returns the local file storage path for a given file key"""
        return os.path.join(self.local_path, self.object_path, key)

    @staticmethod
    def calculate_s3_etag(file, chunk_size=8 * 1024 * 1024):
        """Calculates the S3 custom e-tag (a specially formatted MD5 hash)"""
        md5s = []

        while True:
            data = file.read(chunk_size)
            if not data:
                break
            md5s.append(hashlib.md5(data))

        if len(md5s) == 1:
            return '"{}"'.format(md5s[0].hexdigest())

        digests = b''.join(m.digest() for m in md5s)
        digests_md5 = hashlib.md5(digests)
        return '"{}-{}"'.format(digests_md5.hexdigest(), len(md5s))

    def _get_obj(self, key, tag):
        """Downloads an object at key to file path, checking to see if an existing file matches the current hash"""
        log = logging.getLogger(__name__)
        path = os.path.join(self.local_path, key)
        os.makedirs(os.path.dirname(path))
        dl_flag = True
        try:
            f = open(path, 'rb')
            if tag == self.calculate_s3_etag(f):
                log.info('Cache Hit')
                dl_flag = False
            f.close()
        except FileNotFoundError as e:
            pass

        if dl_flag:
            log.info('Cache Miss')
            self.bucket.download_file(key, path)

    def sync(self):
        """Syncs the local and remote S3 copies"""
        pool = multiprocessing.Pool()
        keys = [(obj.key, obj.e_tag) for obj in self.bucket.objects.filter(Prefix=self.object_path)]
        pool.starmap(self._get_obj, keys)

    def del_local(self):
        """Deletes all local files"""
        shutil.rmtree(self.local_path)
