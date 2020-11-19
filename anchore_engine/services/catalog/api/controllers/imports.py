import datetime
from uuid import uuid4
from hashlib import sha256
from connexion import request

from anchore_engine.apis import exceptions as api_exceptions
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.subsys.object_store import manager
from anchore_engine.common.helpers import make_response_error
from anchore_engine.subsys import logger
from anchore_engine.db import session_scope
from anchore_engine.db.entities.catalog import ImageImportOperation, ImageImportContent, ImportState
from anchore_engine.utils import datetime_to_rfc3339
from anchore_engine.common.schemas import ImportManifest

authorizer = get_authorizer()

IMPORT_BUCKET = 'image_content_imports'

MAX_UPLOAD_SIZE = 100 * 1024 * 1024 # 100 MB
OPERATION_EXPIRATION_DELTA = datetime.timedelta(hours=24)
supported_content_types = ["packages"]


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_import_packages(operation_id: str):
    try:
        with session_scope() as db_session:
            resp = [x.digest for x in db_session.query(ImageImportContent).join(ImageImportContent.operation).filter(ImageImportOperation.account==ApiRequestContextProxy.namespace(), ImageImportOperation.uuid==operation_id).all()]

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def create_operation():
    """
    POST /imports/images

    :return:
    """
    try:
        with session_scope() as db_session:
            op = ImageImportOperation()
            op.account = ApiRequestContextProxy.namespace()
            op.status = ImportState.pending
            op.expires_at = datetime.datetime.utcnow() + OPERATION_EXPIRATION_DELTA

            db_session.add(op)
            db_session.flush()
            resp = op.to_json()

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_operations():
    """
    GET /imports/images

    :return:
    """
    try:
        with session_scope() as db_session:
            resp = [x.to_json() for x in db_session.query(ImageImportOperation).filter_by(account=ApiRequestContextProxy.namespace()).all()]

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_operation(operation_id):
    """
    GET /imports/images/{operation_id}

    :param operation_id:
    :return:
    """
    try:
        with session_scope() as db_session:
            record = db_session.query(ImageImportOperation).filter_by(account=ApiRequestContextProxy.namespace(), uuid=operation_id).one_or_none()
            if record:
                resp = record.to_json()
            else:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


# @authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
# def get_content_uploads(operation_id, content_type):
#     with session_scope() as db_session:
#         uploads = db_session.query(ImageImportContent).join(ImageImportContent.operation).filter(ImageImportOperation.account==ApiRequestContextProxy.namespace(), ImageImportOperation.uuid==operation_id).filter(ImageImportContent.operation_id==operation_id, ImageImportContent.content_type==content_type).all()
#         return [{'uuid': x.uuid, 'digest': x.digest, 'created_at': x.created_at} for x in uploads], 200


def generate_import_bucket():
    return IMPORT_BUCKET


def generate_key(account, op_id, content_type, digest):
    return '{}/{}/{}/{}'.format(account, op_id, content_type, digest)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_dockerfile(operation_id):
    logger.info("Got dockerfile: {}".format(request.data))
    return '', 200

@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_packages(operation_id, sbom):
    """
    POST /imports/images/{operation_id}/packages

    :param operation_id:
    :param content:
    :return:
    """
    try:
        with session_scope() as db_session:
            record = db_session.query(ImageImportOperation).filter_by(account=ApiRequestContextProxy.namespace(), uuid=operation_id).one_or_none()
            if not record:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        if not request.content_length:
            raise api_exceptions.BadRequest(message='Request must contain content-length header', detail={})
        elif request.content_length > 100 * 1024 * 1204:
            raise api_exceptions.BadRequest(message='too large. Max size of 100MB supported for content', detail={'content-length': request.content_length})

        hasher = sha256(request.data)  # Direct bytes hash
        digest = hasher.digest().hex()

        import_bucket = generate_import_bucket()
        key = generate_key(ApiRequestContextProxy.namespace(), operation_id, 'packages', digest)

        with session_scope() as db_session:
            content_record = ImageImportContent()
            content_record.account = ApiRequestContextProxy.namespace()
            content_record.digest = digest
            content_record.content_type = 'packages'
            content_record.operation_id = operation_id

            # TODO:
            #content_record.stored_bucket = import_bucket
            #content_record.stored_key = key

            db_session.add(content_record)
            db_session.flush()

            try:
                mgr = manager.object_store.get_manager()
                resp = mgr.put_document(ApiRequestContextProxy.namespace(), import_bucket, archiveId=key, data=sbom)
            except:
                db_session.delete(content_record)
                raise

        resp = {
            "digest": digest,
            "created_at": datetime_to_rfc3339(datetime.datetime.utcnow())
        }

        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return make_response_error(ex, in_httpcode=ex.__response_code__), ex.__response_code__
    except Exception as ex:
        logger.exception('Unexpected error in api processing')
        return make_response_error(ex, in_httpcode=500), 500


# def invalid_import_manifest_digests(operation_id: str, manifest: ImportManifest) -> set:
#     """
#
#     :param operation_id:
#     :param manifest:
#     :return: set of invalid content references, emtpy set if the content manifest checks out
#     """
#
#     # Verify the content in the manifest exists and has the right digests.
#     contents = {x.get('uuid'): x.get('digest') for x in manifest.metadata}
#
#     with session_scope() as db_session:
#         content_records = db_session.query(ImageImportContent).filter(ImageImportContent.operation_id == operation_id, ImageImportContent.digest.in_([x[0] for x in contents.keys()])).all()
#         found_content = set([x.uuid for x in content_records])
#
#         missing_content = set(contents.keys()).difference(found_content)
#         if missing_content and len(missing_content) > 0:
#             return missing_content
#         else:
#             return set()
