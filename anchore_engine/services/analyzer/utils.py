import time

import anchore_engine.subsys
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.subsys import logger


def fulltag_from_detail(image_detail: dict) -> str:
    """
    Return a fulltag string from the detail record

    :param image_detail:
    :return:
    """
    return image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']


def emit_events(client: CatalogClient, analysis_events: list):
    for event in analysis_events:
        try:
            client.add_event(event)
        except:
            logger.error('Ignoring error sending event')


# def create_analysis(client: CatalogClient, image_digest, image_record):
#     client.add_image(tag='docker.io/test/tag', digest=image_digest, dockerfile='', annotations={}, created_at=None, allow_dockerfile_update=False)
#     # Hack, just updated it quickly now
#     update_catalog_image_status(client, image_digest)


def update_analysis_started(client: CatalogClient, image_digest, image_record):
    """
    Wrapper for updating the analysis status to success

    :param client:
    :param image_digest:
    :param image_record:
    :return:
    """
    return update_catalog_image_status(client, image_digest, image_record, new_analysis_status=anchore_engine.subsys.taskstate.working_state('analyze'))


def update_analysis_complete(client: CatalogClient, image_digest, image_record):
    """
    Wrapper for updating the analysis status to success

    :param client:
    :param image_digest:
    :param image_record:
    :return:
    """
    image_record['analyzed_at'] = int(time.time())
    return update_catalog_image_status(client, image_digest, image_record, new_analysis_status=anchore_engine.subsys.taskstate.complete_state('analyze'))


def update_analysis_failed(client: CatalogClient, image_digest, image_record):
    """
    Wrapper to mark an image as failed analysis

    :param client:
    :param image_digest:
    :param image_record:
    :return:
    """
    return update_catalog_image_status(client, image_digest, image_record, new_analysis_status=anchore_engine.subsys.taskstate.fault_state('analyze')) #new_image_status=anchore_engine.subsys.taskstate.fault_state('image_status'))


def update_catalog_image_status(client: CatalogClient, image_digest: str, image_record: dict, new_analysis_status=None, new_image_status=None) -> dict:
    """
    Update the analysis and/or image status for the record, one of new_analysis_status and new_image_status must be non-None

    :param client:
    :param image_digest:
    :param image_record:
    :param new_analysis_status: str new analysis_status value, options
    :param new_image_status: str new image status value, optional
    :return:
    """
    assert image_digest is not None
    assert image_record is not None
    assert new_analysis_status or new_image_status

    if new_analysis_status:
        image_record['analysis_status'] = new_analysis_status

    if new_image_status:
        image_record['image_status'] = new_image_status

    rc = client.update_image(image_digest, image_record)
    return image_record