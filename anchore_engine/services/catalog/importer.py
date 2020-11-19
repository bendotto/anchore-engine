import retrying

from anchore_engine.apis import exceptions as api_exceptions
from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.common.helpers import make_response_error
from anchore_engine.common.schemas import ImportManifest, ImportQueueMessage, ImageMetadata
from anchore_engine.db import ImageImportContent, session_scope, ImageImportOperation, db_catalog_image
from anchore_engine.db.entities.catalog import ImportState
from anchore_engine.services.catalog.catalog_impl import add_or_update_image
from anchore_engine.subsys import logger
from anchore_engine.util.docker import DockerImageReference

IMPORT_QUEUE = 'images_to_analyze'


@retrying.retry(wait_fixed=1000, stop_max_attempt_number=3)
def queue_import_task(account: str, operation_id: str, manifest: ImportManifest) -> bool:
    """
    Queue the task for analysis

    :param account:
    :param manifest:
    :return:
    """
    # Replace this is a state watcher, similar to the image state handlers
    logger.info('Queueing import taks for account %s', account)

    task = ImportQueueMessage()
    task.account = account
    task.manifest = manifest
    task.operation_uuid = operation_id

    q_client = internal_client_for(SimpleQueueClient, userId=account)
    resp = q_client.enqueue(name=IMPORT_QUEUE, inobj=task.to_json())
    logger.debug('Queue task response: %s', str(resp))
    return True


def verify_import_manifest_content(operation_id: str, import_manifest: ImportManifest, db_session):
    """
    Verify the content of the manifest and return a list of any content digests referenced in the manifest but not found in the system
    :param operation_id:
    :param import_manifest:
    :param db_session:
    :return: set of missing content digests
    """

    content_records = db_session.query(ImageImportContent).filter(ImageImportContent.operation_id == operation_id, ImageImportContent.digest.in_(import_manifest.contents)).all()
    found_content = {x.digest for x in content_records}
    return set(import_manifest.contents).difference(found_content)


def finalize_import_operation(db_session, account: str, operation_id: str, import_manifest: ImportManifest):
    """
    Finalize the import operation itself

    :param db_session:
    :param account:
    :param operation_id:
    :param import_manifest:
    :return:
    """
    try:
        record = db_session.query(ImageImportOperation).filter_by(account=account, uuid=operation_id).one_or_none()
        if not record:
            raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        if record.status != ImportState.pending:
            raise api_exceptions.ConflictingRequest(message='Invalid operation status. Must be in pending state to finalize', detail={'status': record.status.value})

        not_found_digests = verify_import_manifest_content(operation_id, import_manifest, db_session)
        if not_found_digests:
            raise api_exceptions.BadRequest(message='Referenced digests not found', detail={'digests': list(not_found_digests)})

        # try:
        #     # Update the status
        #     record.status = ImportState.queued
        #     queue_import_task(account, operation_id, import_manifest)
        # except:
        #     logger.debug_exception("Failed to queue task message. Setting failed status")
        #     record.status = ImportState.failed
        #     raise

        db_session.flush()
        return record
    except api_exceptions.AnchoreApiError:
        raise
    except Exception as ex:
        logger.debug_exception('Uncaught exception in finalization path')
        return make_response_error(ex, in_httpcode=500), 500


def import_image(dbsession, account: str, operation_id: str,  import_manifest: ImportManifest, dockerfile_content: str = None, force: bool = False) -> dict:

    logger.debug("Processing import image request with source operation_id = {}".format(operation_id))

    # Check for dockerfile updates to an existing image
    found_img = db_catalog_image.get(imageDigest=import_manifest.digest, userId=account, session=dbsession)
    if found_img and not force:
        raise BadRequest('Cannot specify dockerfile for an image that already exists unless using force=True for re-analysis', detail={'digest': import_manifest.digest})

    logger.debug("Loading image info using import operation id %s", operation_id)
    image_references = []
    for t in import_manifest.tags:
        r = DockerImageReference.from_string(t)
        r.digest = import_manifest.digest
        r.image_id = import_manifest.local_image_id if import_manifest.local_image_id else import_manifest.digest # TODO: fix this
        image_references.append(r)

    if not (image_references and image_references[0].has_digest()):
        raise ValueError('Must have image digest in image reference')

    # Finalize the import
    finalized_record = finalize_import_operation(dbsession, account, operation_id, import_manifest)

    # Get the dockerfile content if available
    dockerfile_mode = "Actual" if dockerfile_content else "Guessed"
    dockerfile_content = ''

    manifest = import_manifest.to_json()
    parent_manifest = import_manifest.to_json()

    # Update the db for the image record
    image_records = add_or_update_image(dbsession,
                                        account,
                                        image_references[0].image_id,
                                        tags=[x.tag_pullstring() for x in image_references],
                                        digests=[x.digest_pullstring() for x in image_references],
                                        parentdigest=import_manifest.parent_digest if import_manifest.parent_digest else import_manifest.digest,
                                        created_at=import_manifest.metadata.created_at,
                                        dockerfile=dockerfile_content,
                                        dockerfile_mode=dockerfile_mode,
                                        manifest=manifest,
                                        parent_manifest=parent_manifest,
                                        annotations=import_manifest.annotations)
    if image_records:
        image_record = image_records[0]
    else:
        raise Exception('No record updated/inserted')

    return image_record