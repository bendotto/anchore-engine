import time
from .tasks import WorkerTask
from anchore_engine.subsys import logger
#from anchore_engine.clients.localanchore_standalone import generate_image_export
from anchore_engine.common.schemas import ImportManifest, ImportQueueMessage, ValidationError
from anchore_engine.utils import timer
from anchore_engine.subsys import taskstate
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient


minimal_content_types = [
    'manifest',
    'packages'
]


def map_content(manifest: ImportManifest) -> dict:
    """
    Load the content from the import manifest and convert it into the system internal format

    :param manifest:
    :return: analysis report as would have been output by the analyzers
    """

    # fake_id = uuid.uuid4().hex
    # fake_digest = 'sha256:' + sha256(bytes(fake_id, 'utf-8')).hexdigest()
    # analyzer_report = {}
    # image_size = manifest.metadata.image_size
    # full_tag = manifest.tags[0] # Choose 1 to start
    # image_architecture = manifest.metadata.platform.architecture
    # dockerfile_contents = manifest.docker_file
    # layers = manifest.metadata.layers
    # docker_history = []
    # dockerfile_mode = 'actual' if dockerfile_contents else 'generated'
    # familytree = layers
    # analyzer_manifest = {}
    # analysis_report = generate_image_export(fake_id, analyzer_report, image_size, full_tag, docker_history, dockerfile_mode, dockerfile_contents, layers, familytree, image_architecture, fake_digest, analyzer_manifest)
    analysis_report = {}
    return analysis_report


def finalize_image():
    logger.info("Finalizing image import")
    return True


def save_content(content):
    logger.info("Saving imported content into catalog")
    return True


class InvalidImageStateException(Exception):
    pass


class MissingRequiredContentException(Exception):
    pass


def check_catalog_image(digest: str, client: CatalogClient):
    """
    Checks if the image record is present in the catalog and returns the record if so and the state is valid. Raises
    an exception if the state is conflicting

    :param digest:
    :param client:
    :return:
    """
    image_record = client.get_image(digest)
    if image_record and image_record['analysis_status'] != taskstate.fault_state('analyze'):
        # TODO: revisit here, probably need to handle a force option
        raise InvalidImageStateException('Image record exists and is in non-failed state')

    return image_record


def initialize_new_image(import_manifest: ImportManifest, client: CatalogClient):
    """
    Build new image record from scratch and save it in Catalog via API

    :param import_manifest:
    :param client:
    :return:
    """
    resp = client.add_image(tag=import_manifest.tags[0] or None, digest=import_manifest.metadata.digest, annotations=import_manifest.annotations)
    resp = client.update_image(imageDigest=import_manifest.metadata.digest, image_record=resp)
    return resp


def get_content(account: str, operation_id: str, manifest: ImportManifest, content_type: str, client: CatalogClient):
    # NOTE: need to add the bucket and key into the message queue so that we don't have to share logic to fetch the content
    bucket = 'image_content_imports' # wrong
    for digest in manifest.contents:
        key = '{}/{}/{}/{}'.format(account, operation_id, content_type, digest)
        content = client.get_document(bucket, key)
        if not content:
            raise MissingRequiredContentException('no content found in object store for content-type = %s and digest %s', content_type, digest)


def import_image(import_manifest: ImportManifest) -> bool:
    # Do v1 import
    logger.info('Importing image %s', import_manifest.metadata.digest)

    content = map_content(import_manifest)
    save_content(content)
    finalize_image()
    return True


class ImportTask(WorkerTask):
    """
    The task to import an analysis performed externally
    """

    def __init__(self, message: ImportQueueMessage):
        super().__init__()
        self.message = message
        self.account = message.account

    def execute(self):
        logger.info('Executing import task. Account = %s, Id = %s', self.account, self.task_id)
        import_image(self.message.manifest)
        logger.info('Import task %s complete', self.task_id)


def is_import_message(payload_json: dict) -> bool:
    try:
        return ImportQueueMessage.from_json(payload_json) is not None
    except ValidationError:
        return False

