from hashlib import sha256
import uuid
from .tasks import WorkerTask
from anchore_engine.subsys import logger
from anchore_engine.clients.localanchore_standalone import generate_image_export
from anchore_engine.common.schemas import ImportManifest, ImportQueueMessage


def map_content(manifest: ImportManifest) -> dict:
    """
    Load the content from the import manifest and convert it into the system internal format

    :param manifest:
    :return: analysis report as would have been output by the analyzers
    """

    #generate_image_export(imageId, analyzer_report, imageSize, fulltag, docker_history, dockerfile_mode, dockerfile_contents, layers, familytree, imageArch, rdigest, analyzer_manifest):
    fake_id = uuid.uuid4().hex
    fake_digest = 'sha256:' + sha256(bytes(fake_id, 'utf-8')).hexdigest()
    analyzer_report = {}
    image_size = manifest.metadata.image_size



    analysis_report = generate_image_export()
    return analysis_report


def finalize_image():


    return True


def save_content():
    return True


def import_image(import_manifest: dict) -> bool:
    # Do v1 import
    logger.info('Importing image %s', import_manifest.get('image_digest'))

    map_content(import_manifest)

    save_content()
    finalize_image()

    return True


class ImportTask(WorkerTask):
    def __init__(self):
        super().__init__()
        self.account = None
        self.import_manifest = None

    def exec(self):
        logger.info('Executing import task. Account = s, Id = %s', self.account, self.task_id)

        logger.info('Import task %s complete', self.task_id)


def process_import_job(import_task: ImportTask):
    import_task.run()


def is_import_task(payload_json: dict) -> bool:
    try:
        return ImportQueueMessage.from_json(payload_json) is not None
    except ValidationError:
        return False

