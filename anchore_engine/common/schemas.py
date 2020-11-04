"""
Shared global location for all JSON serialization schemas. They should only reference each-other in this module so it
can import cleanly into any service or module.
"""

from anchore_engine.apis.serialization import JsonSerializable, Schema, ValidationError, post_load, fields


# TODO: This is not enforced in the interface yet, but should be the input and return type for queue operations in this API
class QueueMessage(JsonSerializable):
    """
    The generic queue message object
    """

    class QueueMessageV1Schema(Schema):
        """
        Example for an image analysis message:
            { 'created_at': 1604474221,
                'data': {
                    'imageDigest': 'sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88',
                    'manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1512, "digest": "sha256:b7c5ffe56db790f91296bcebc5158280933712ee2fc8e6dc7d6c96dbb1632431"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2387850, "digest": "sha256:c1e54eec4b5786500c19795d1fc604aa7302aee307edfe0554a5c07108b77d48"}]}',
                    'parent_manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json", "manifests": [{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": 528, "digest": "sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88", "platform": {"architecture": "amd64", "os": "linux"}}]}',
                    'userId': 'admin'},
                'dataId': 'e05953b79c0f8653ae0650e461db4c90',
                'last_updated': 1604474221,
                'max_tries': 0,
                'popped': True,
                'priority': False,
                'queueId': 32013,
                'queueName': 'images_to_analyze',
                'receipt_handle': None,
                'record_state_key': 'active',
                'record_state_val': None,
                'tries': 0,
                'userId': 'system',
                'visible_at': None
            }

        """
        account = fields.String(data_key='userId')
        created_at = fields.Int(required=True)  # Epoch timestamp
        last_updated = fields.Int(required=True)  # Epoch timestamp
        queue_id = fields.Int(required=True, data_key='queueId')
        queue_name = fields.String(required=True, data_key='queueName')
        data = fields.Dict(required=True)
        data_id = fields.String(data_key='dataId', required=True)
        receipt_handle = fields.String(allow_none=True)
        record_state_key = fields.String(allow_none=True)
        record_state_val = fields.String(allow_none=True)
        tries = fields.Int(allow_none=True)
        max_tries = fields.Int(allow_none=True)
        popped = fields.Bool(allow_none=True)
        priority = fields.Bool(allow_none=True)
        visible_at = fields.Int(allow_none=True)
        version = fields.String(default='1', missing='1') # New version field to support future message schema updates

        @post_load
        def make(self, data, **kwargs):
            return QueueMessage(**data)

    __schema__ = QueueMessageV1Schema()

    def __init__(self, account=None, queue_id=None, queue_name=None, data=None, data_id=None, receipt_handle=None, record_state_key=None, record_state_val=None, tries=None, max_tries=None, popped=None, visible_at=None, priority=None, created_at=None, last_updated=None, version=None):
        self.account = account
        self.queue_id = queue_id
        self.queue_name = queue_name
        self.data = data
        self.data_id = data_id
        self.receipt_handle = receipt_handle
        self.record_state_key = record_state_key
        self.record_state_val = record_state_val
        self.tries = tries
        self.max_tries = max_tries
        self.popped = popped
        self.created_at = created_at
        self.last_updated = last_updated
        self.visible_at = visible_at
        self.priority = priority
        self.version = None


class AnalysisQueueMessage(JsonSerializable):
    """
    A queue message payload requesting analysis of an image, for consumption by the worker service.
    """

    class AnalysisQueueMessageV1Schema(Schema):
        """
        Example for an image analysis message:
        {
            'imageDigest': 'sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88',
            'manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1512, "digest": "sha256:b7c5ffe56db790f91296bcebc5158280933712ee2fc8e6dc7d6c96dbb1632431"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2387850, "digest": "sha256:c1e54eec4b5786500c19795d1fc604aa7302aee307edfe0554a5c07108b77d48"}]}',
            'parent_manifest': '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json", "manifests": [{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": 528, "digest": "sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88", "platform": {"architecture": "amd64", "os": "linux"}}]}',
            'userId': 'admin'},
        }

        """
        account = fields.String(data_key='userId')
        image_digest = fields.String(data_key='imageDigest')
        manifest = fields.String()
        parent_manifest = fields.String()
        type = fields.String(default='analysis')

        @post_load
        def make(self, data, **kwargs):
            return AnalysisQueueMessage(**data)

    __schema__ = AnalysisQueueMessageV1Schema()

    def __init__(self, account=None, image_digest=None, manifest=None, parent_manifest=None):
        self.account = account
        self.image_digest = image_digest
        self.manifest = manifest
        self.parent_manifest = parent_manifest


class ImageLayerMetadata(JsonSerializable):
    class ImageLayerMetadataV1Schema(Schema):
        digest = fields.String()
        size = fields.Int()
        location = fields.String(allow_none=True) # To allow capturing foreign url references

        @post_load
        def make(self, data, **kwarg):
            return ImageLayerMetadata(**data)

    __schema__ = ImageLayerMetadataV1Schema()

    def __init__(self, digest=None, size=None, location=None):
        self.digest = digest
        self.size = size
        self.location = location


class ImageMetadata(JsonSerializable):
    """
    Information about the structure, and attributes of the image itself.
    Should not contain any data that must be extracted from inside the image.

    For example, this data is from things like `docker inspect` or `podman inspect`

    """
    class ImageMetadataV1Schema(Schema):
        digest = fields.String(required=True)
        local_image_id = fields.String()
        layers = fields.List(fields.Nested(ImageLayerMetadata.ImageLayerMetadataV1Schema))
        size = fields.Int()
        docker_file = fields.String(allow_none=True)
        build_file = fields.String(allow_none=True)
        annotations = fields.Mapping(keys=fields.String(), values=fields.String())


class ImportManifest(JsonSerializable):
    class ImportManifestV1Schema(Schema):
        metadata = fields.Nested(ImageMetadata.ImageMetadataV1Schema)

        @post_load
        def make(self, data, **kwargs):
            return ImportManifest(**data)

    __schema__ = ImportManifestV1Schema()

    def __init__(self, metadata = None):
        self.metadata = metadata


class ImportQueueMessage(JsonSerializable):
    class ImportQueueMessageV1Schema(Schema):
        """
        Example for an image import message:
        {
            'manifest': {
            <ImportManifest>
            }
            'account': 'admin'},
        }

        """
        account = fields.String(data_key='userId')
        manifest = fields.Nested(ImportManifest)

        @post_load
        def make(self, data, **kwargs):
            return ImportQueueMessage(**data)

    __schema__ = ImportQueueMessageV1Schema()

    def __init__(self, account=None, manifest=None):
        self.account = account
        self.manifest = manifest
