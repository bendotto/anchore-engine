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
from anchore_engine.db.entities.catalog import (
    ImageImportOperation,
    ImageImportContent,
    ImportState,
)
from anchore_engine.utils import datetime_to_rfc3339, ensure_str, ensure_bytes
from anchore_engine.common.schemas import ImportManifest

authorizer = get_authorizer()

IMPORT_BUCKET = "image_content_imports"

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
OPERATION_EXPIRATION_DELTA = datetime.timedelta(hours=24)
supported_content_types = ["packages"]


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_import_packages(operation_id: str):
    try:
        with session_scope() as db_session:
            resp = [
                x.digest
                for x in db_session.query(ImageImportContent)
                .join(ImageImportContent.operation)
                .filter(
                    ImageImportOperation.account == ApiRequestContextProxy.namespace(),
                    ImageImportOperation.uuid == operation_id,
                )
                .all()
            ]

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
            resp = [
                x.to_json()
                for x in db_session.query(ImageImportOperation)
                .filter_by(account=ApiRequestContextProxy.namespace())
                .all()
            ]

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
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if record:
                resp = record.to_json()
            else:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def invalidate_operation(operation_id):
    """
    DELETE /imports/images/{operation_id}

    :param operation_id:
    :return:
    """
    try:
        with session_scope() as db_session:
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if record:
                if record.status not in [ImportState.invalidated, ImportState.complete]:
                    record.status = ImportState.invalidated
                    db_session.flush()

                resp = record.to_json()
            else:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def update_operation(operation_id, operation):
    """
    PUT /imports/images/{operation_id}

    Will only update the status, no other fields

    :param operation_id:
    :param operation: content of operation to update
    :return:
    """
    if not operation.get("status"):
        raise api_exceptions.BadRequest("status field required", detail={})

    try:
        with session_scope() as db_session:
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if record:
                if record.status.is_active():
                    record.status = operation.get("status")
                    db_session.flush()

                resp = record.to_json()
            else:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


def generate_import_bucket():
    return IMPORT_BUCKET


def generate_key(account, op_id, content_type, digest):
    return "{}/{}/{}/{}".format(account, op_id, content_type, digest)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_dockerfile(operation_id):
    logger.info("Got dockerfile: {}".format(request.data))
    return "", 200


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_packages(operation_id):
    """
    POST /imports/images/{operation_id}/packages

    :param operation_id:
    :param sbom:
    :return:
    """

    return content_upload(operation_id, "packages", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_dockerfile(operation_id):
    """
    POST /imports/images/{operation_id}/dockerfile

    :param operation_id:
    :param sbom:
    :return:
    """

    return content_upload(operation_id, "dockerfile", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_manifest(operation_id):
    """
    POST /imports/images/{operation_id}/manifest

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "manifest", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_parent_manifest(operation_id):
    """
    POST /imports/images/{operation_id}/parent_manifest

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "parent_manifest", request)


def content_upload(operation_id, content_type, request):
    """
    Generic handler for multiple types of content uploads. Still operates at the API layer

    :param operation_id:
    :param content_type:
    :param request:
    :return:
    """
    try:
        with session_scope() as db_session:
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if not record:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

            if not request.content_length:
                raise api_exceptions.BadRequest(
                    message="Request must contain content-length header", detail={}
                )
            elif request.content_length > MAX_UPLOAD_SIZE:
                raise api_exceptions.BadRequest(
                    message="too large. Max size of 100MB supported for content",
                    detail={"content-length": request.content_length},
                )

            digest, created_at = save_import_content(
                db_session, operation_id, request.data, content_type
            )

        resp = {"digest": digest, "created_at": created_at}

        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


def save_import_content(
    db_session, operation_id: str, content: bytes, content_type: str
) -> tuple:
    """
    Generic handler for content type saving that does not do any validation.

    :param operation_id:
    :param sbom:
    :return:
    """
    hasher = sha256(content)  # Direct bytes hash
    digest = hasher.digest().hex()

    found_content = (
        db_session.query(ImageImportContent)
        .filter(
            ImageImportContent.operation_id == operation_id,
            ImageImportContent.content_type == content_type,
            ImageImportContent.digest == digest,
        )
        .one_or_none()
    )

    if found_content:
        logger.info("Found existing record {}".format(found_content.digest))
        # Short circuit since already present
        return found_content.digest, found_content.created_at

    import_bucket = generate_import_bucket()
    key = generate_key(
        ApiRequestContextProxy.namespace(), operation_id, content_type, digest
    )

    content_record = ImageImportContent()
    content_record.account = ApiRequestContextProxy.namespace()
    content_record.digest = digest
    content_record.content_type = content_type
    content_record.operation_id = operation_id
    content_record.storage_bucket = import_bucket
    content_record.storage_key = key

    db_session.add(content_record)
    db_session.flush()

    mgr = manager.object_store.get_manager()
    resp = mgr.put_document(
        ApiRequestContextProxy.namespace(), import_bucket, key, ensure_str(content)
    )
    if not resp:
        # Abort the transaction
        raise Exception("Could not save into object store")

    return digest, content_record.created_at
