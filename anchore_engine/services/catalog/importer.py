import enum
import retrying
import datetime

from anchore_engine.apis import exceptions as api_exceptions
from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.common.helpers import make_response_error
from anchore_engine.common.schemas import (
    ImportManifest,
    ImportQueueMessage,
    ImageMetadata,
)
from anchore_engine.db import (
    ImageImportContent,
    session_scope,
    ImageImportOperation,
    db_catalog_image,
)
from anchore_engine.db.entities.catalog import ImportState
from anchore_engine.services.catalog.catalog_impl import add_or_update_image
from anchore_engine.subsys import logger
from anchore_engine.util.docker import DockerImageReference

IMPORT_QUEUE = "images_to_analyze"


class ImportTypes(enum.Enum):
    """
    The types of content supported for upload
    """

    packages = 'packages'
    dockerfile = 'dockerfile'
    manifest = 'manifest'
    parent_manifest = 'parent_manifest'


@retrying.retry(wait_fixed=1000, stop_max_attempt_number=3)
def queue_import_task(
    account: str, operation_id: str, manifest: ImportManifest
) -> bool:
    """
    Queue the task for analysis

    :param account:
    :param manifest:
    :return:
    """
    # Replace this is a state watcher, similar to the image state handlers
    logger.info("Queueing import task for account %s", account)

    task = ImportQueueMessage()
    task.account = account
    task.manifest = manifest
    task.operation_uuid = operation_id

    q_client = internal_client_for(SimpleQueueClient, userId=account)
    resp = q_client.enqueue(name=IMPORT_QUEUE, inobj=task.to_json())
    logger.debug("Queue task response: %s", str(resp))
    return True


def verify_import_manifest_content(
    db_session, operation_id: str, import_manifest: ImportManifest
):
    """
    Verify the content of the manifest and return a list of any content digests referenced in the manifest but not found in the system
    :param operation_id:
    :param import_manifest:
    :param db_session:
    :return: set of missing content digests
    """

    if (import_manifest.contents.packages and
        db_session.query(ImageImportContent)
        .filter(
            ImageImportContent.operation_id == operation_id,
            ImageImportContent.digest == import_manifest.contents.packages,
            ImageImportContent.content_type == ImportTypes.packages.value
        )
        .one_or_none()
        is None
    ):
        raise ValueError(import_manifest.contents.packages)

    if (import_manifest.contents.dockerfile and
        db_session.query(ImageImportContent)
        .filter(
            ImageImportContent.operation_id == operation_id,
            ImageImportContent.digest == import_manifest.contents.dockerfile,
            ImageImportContent.content_type == ImportTypes.dockerfile.value
        )
        .one_or_none()
        is None
    ):
        raise ValueError(import_manifest.contents.dockerfile)

    if (import_manifest.contents.manifest and
        db_session.query(ImageImportContent)
        .filter(
            ImageImportContent.operation_id == operation_id,
            ImageImportContent.digest == import_manifest.contents.manifest,
            ImageImportContent.content_type == ImportTypes.manifest.value
        )
        .one_or_none()
        is None
    ):
        raise ValueError(import_manifest.contents.manifest)

    if (import_manifest.contents.parent_manifest and
        db_session.query(ImageImportContent)
        .filter(
            ImageImportContent.operation_id == operation_id,
            ImageImportContent.digest == import_manifest.contents.parent_manifest,
            ImageImportContent.content_type == ImportTypes.parent_manifest.value,
        )
        .one_or_none()
        is None
    ):
        raise ValueError(import_manifest.contents.parent_manifest)

    return None


def finalize_import_operation(
    db_session, account: str, operation_id: str, import_manifest: ImportManifest
) -> dict:
    """
    Finalize the import operation itself

    :param db_session:
    :param account:
    :param operation_id:
    :param import_manifest:
    :return:
    """
    record = (
        db_session.query(ImageImportOperation)
        .filter_by(account=account, uuid=operation_id)
        .one_or_none()
    )
    if not record:
        raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

    if record.status != ImportState.pending:
        # TODO: Fix these to not be API exception, just regular confict/value error exceptions since this isn't the API layer
        raise api_exceptions.ConflictingRequest(
            message="Invalid operation status. Must be in pending state to finalize",
            detail={"status": record.status.value},
        )

    try:
        verify_import_manifest_content(db_session, operation_id, import_manifest)
    except ValueError as ex:
        raise api_exceptions.BadRequest(
            message="One or more referenced content digests not found for the operation id",
            detail={"digest": ex.args[0]},
        )

    try:
        # Update the status
        record.status = ImportState.processing
        queue_import_task(account, operation_id, import_manifest)
    except:
        logger.debug_exception("Failed to queue task message. Setting failed status")
        record.status = ImportState.failed
        raise

    db_session.flush()
    return record


def import_image(
    dbsession,
    account: str,
    operation_id: str,
    import_manifest: ImportManifest,
    force: bool = False,
    annotations: dict = None,
) -> dict:
    """
    Process the image import finalization, creating the new 'image' record and setting the proper state for queueing

    :param dbsession:
    :param account:
    :param operation_id:
    :param import_manifest:
    :param force:
    :param annotations:
    :return:
    """

    logger.debug(
        "Processing import image request with source operation_id = {}".format(
            operation_id
        )
    )

    # Add annotation indicating this is an import
    annotations = add_import_annotations(import_manifest, annotations)

    # Check for dockerfile updates to an existing image
    found_img = db_catalog_image.get(
        imageDigest=import_manifest.digest, userId=account, session=dbsession
    )
    if found_img and not force:
        raise BadRequest(
            "Cannot reload image that already exists unless using force=True for re-analysis",
            detail={"digest": import_manifest.digest},
        )

    logger.debug("Loading image info using import operation id %s", operation_id)
    image_references = []
    for t in import_manifest.tags:
        r = DockerImageReference.from_string(t)
        r.digest = import_manifest.digest

        if import_manifest.local_image_id:
            r.image_id = import_manifest.local_image_id
        else:
            r.image_id = import_manifest.digest

        image_references.append(r)

    if not (image_references and image_references[0].has_digest()):
        raise ValueError("Must have image digest in image reference")

    # Finalize the import
    finalize_import_operation(dbsession, account, operation_id, import_manifest)

    # Get the dockerfile content if available
    dockerfile_content = ""
    dockerfile_mode = "Guessed"

    manifest = import_manifest.to_json()
    parent_manifest = ""

    # Update the db for the image record
    image_records = add_or_update_image(
        dbsession,
        account,
        image_references[0].image_id,
        tags=[x.tag_pullstring() for x in image_references],
        digests=[x.digest_pullstring() for x in image_references],
        parentdigest=import_manifest.parent_digest
        if import_manifest.parent_digest
        else import_manifest.digest,
        #created_at=
        dockerfile=dockerfile_content,
        dockerfile_mode=dockerfile_mode,
        manifest=manifest, # Fo now use the import manifest as the image manifest. This will get set properly later
        parent_manifest=parent_manifest,
        annotations=annotations,
    )
    if image_records:
        image_record = image_records[0]
    else:
        raise Exception("No record updated/inserted")

    return image_record


ANCHORE_SYSTEM_ANNOTATION_KEY_PREFIX = "anchore.system/"
IMPORT_OPERATION_ANNOTATION_KEY = ANCHORE_SYSTEM_ANNOTATION_KEY_PREFIX + "import_operation_id"


def add_import_annotations(import_manifest: ImportManifest, annotations: dict = None):
    """
    Add annotations to the image to correlate it with the operation_id it's created from

    :param import_manifest:
    :param annotations:
    :return: dict with merged annotations to track import
    """

    if not annotations:
        annotations = {}

    annotations[IMPORT_OPERATION_ANNOTATION_KEY] = import_manifest.operation_uuid
    return annotations