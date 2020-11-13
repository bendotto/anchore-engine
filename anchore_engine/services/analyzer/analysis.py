import json
import os
import time

import anchore_engine.clients
import anchore_engine.common
from anchore_engine.configuration.localconfig import get_config
import anchore_engine.subsys
from anchore_engine.clients import localanchore_standalone
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.subsys import logger, events as events, metrics, taskstate
from anchore_engine.common.schemas import AnalysisQueueMessage, ValidationError
from anchore_engine.utils import AnchoreException
from anchore_engine.services.analyzer.errors import PolicyEngineClientError, CatalogClientError
from anchore_engine.services.analyzer.tasks import WorkerTask
import typing

ANALYSIS_TIME_SECONDS_BUCKETS = [1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0]


def fulltag_from_detail(image_detail: dict) -> str:
    """
    Return a fulltag string from the detail record

    :param image_detail:
    :return:
    """
    return image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']


def analysis_complete_notification_factory(account, image_digest: str, last_analysis_status: str, analysis_status: str, image_detail: dict, annotations: dict) -> events.UserAnalyzeImageCompleted:
    """
    Return a constructed UserAnalysImageCompleted event from the input data

    :param account:
    :param image_digest:
    :param last_analysis_status:
    :param analysis_status:
    :param image_detail:
    :param annotations:
    :return:
    """

    payload = {
        'last_eval': {'imageDigest': image_digest, 'analysis_status': last_analysis_status, 'annotations': annotations},
        'curr_eval': {'imageDigest': image_digest, 'analysis_status': analysis_status, 'annotations': annotations},
        'subscription_type': 'analysis_update',
        'annotations': annotations or {}
    }

    fulltag = fulltag_from_detail(image_detail)

    return events.UserAnalyzeImageCompleted(user_id=account, full_tag=fulltag, data=payload)


def notify_analysis_complete(image_record: dict, last_analysis_status) -> typing.List[events.UserAnalyzeImageCompleted]:
    """

    :param image_record:
    :return: list of UserAnalyzeImageCompleted events, one for each tag in the image record
    """

    events = []
    image_digest = image_record['imageDigest']
    account = image_record['userId']

    annotations = {}
    try:
        if image_record.get('annotations', '{}'):
            annotations = json.loads(image_record.get('annotations', '{}'))
    except Exception as err:
        logger.warn("could not marshal annotations from json - exception: " + str(err))

    for image_detail in image_record['image_detail']:
        event = analysis_complete_notification_factory(account, image_digest, last_analysis_status, image_record['analysis_status'], image_detail, annotations)
        events.append(event)

    return events


def is_analysis_message(payload_json: dict) -> bool:
    """
    Is the given payload an analysis message payload or some other kind
    :param payload_json:
    :return:
    """
    try:
        return AnalysisQueueMessage.from_json(payload_json) is not None
    except ValidationError:
        return False


def perform_analyze(account, manifest, image_record, registry_creds, layer_cache_enable=False, parent_manifest=None):
    ret_analyze = {}

    localconfig = get_config()
    try:
        tmpdir = localconfig['tmp_dir']
    except Exception as err:
        logger.warn("could not get tmp_dir from localconfig - exception: " + str(err))
        tmpdir = "/tmp"

    use_cache_dir = None
    if layer_cache_enable:
        use_cache_dir = os.path.join(tmpdir, "anchore_layercache")

    # choose the first TODO possible more complex selection here
    try:
        image_detail = image_record['image_detail'][0]
        registry_manifest = manifest
        registry_parent_manifest = parent_manifest
        pullstring = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail['imageDigest']
        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
        logger.debug("using pullstring (" + str(pullstring) + ") and fulltag (" + str(fulltag) + ") to pull image data")
    except Exception as err:
        image_detail = pullstring = fulltag = None
        raise Exception("failed to extract requisite information from image_record - exception: " + str(err))

    timer = int(time.time())
    logger.spew("timing: analyze start: " + str(int(time.time()) - timer))
    logger.info("performing analysis on image: " + str([account, pullstring, fulltag]))

    logger.debug("obtaining anchorelock..." + str(pullstring))
    with anchore_engine.clients.localanchore_standalone.get_anchorelock(lockId=pullstring, driver='nodocker'):
        logger.debug("obtaining anchorelock successful: " + str(pullstring))
        analyzed_image_report, manifest_raw = localanchore_standalone.analyze_image(account, registry_manifest, image_record, tmpdir, localconfig, registry_creds=registry_creds, use_cache_dir=use_cache_dir, parent_manifest=registry_parent_manifest)
        ret_analyze = analyzed_image_report

    logger.info("performing analysis on image complete: " + str(pullstring))

    return ret_analyze


def process_analyzer_job(request: AnalysisQueueMessage, layer_cache_enable):
    """
    Core logic of the analysis process

    :param request:
    :param layer_cache_enable:
    :return:
    """
    global servicename

    timer = int(time.time())
    analysis_events = []

    localconfig = get_config()

    try:
        logger.debug('dequeued object: {}'.format(request.to_json()))

        account = request.account
        image_digest = request.image_digest
        manifest = request.manifest
        parent_manifest = request.parent_manifest

        # check to make sure image is still in DB
        catalog_client = internal_client_for(CatalogClient, account)
        try:
            image_record = catalog_client.get_image(image_digest)
            if not image_record:
                raise Exception("empty image record from catalog")
        except Exception as err:
            logger.warn("dequeued image cannot be fetched from catalog - skipping analysis (" + str(image_digest) + ") - exception: " + str(err))
            return True

        logger.info("image dequeued for analysis: " + str(account) + " : " + str(image_digest))
        if image_record['analysis_status'] != anchore_engine.subsys.taskstate.base_state('analyze'):
            logger.debug("dequeued image is not in base state - skipping analysis")
            return True

        try:
            logger.spew("TIMING MARK0: " + str(int(time.time()) - timer))

            last_analysis_status = image_record['analysis_status']
            image_record['analysis_status'] = anchore_engine.subsys.taskstate.working_state('analyze')
            rc = catalog_client.update_image(image_digest, image_record)

            # actually do analysis
            registry_creds = catalog_client.get_registry()
            try:
                image_data = perform_analyze(account, manifest, image_record, registry_creds, layer_cache_enable=layer_cache_enable, parent_manifest=parent_manifest)
            except AnchoreException as e:
                event = events.ImageAnalysisFailed(user_id=account, image_digest=image_digest, error=e.to_dict())
                analysis_events.append(event)
                raise

            imageId = None
            try:
                imageId = image_data[0]['image']['imageId']
            except Exception as err:
                logger.warn("could not get imageId after analysis or from image record - exception: " + str(err))

            logger.info("adding image analysis data to catalog: account={} imageId={} imageDigest={}".format(account, imageId, image_digest))
            try:
                logger.debug("archiving analysis data")
                rc = catalog_client.put_document('analysis_data', image_digest, image_data)
            except Exception as e:
                err = CatalogClientError(msg='Failed to upload analysis data to catalog', cause=e)
                event = events.SaveAnalysisFailed(user_id=account, image_digest=image_digest, error=err.to_dict())
                analysis_events.append(event)
                raise err

            if rc:
                try:
                    logger.debug("extracting image content data locally")
                    image_content_data = {}
                    all_content_types = localconfig.get('image_content_types', []) + localconfig.get('image_metadata_types', [])
                    for content_type in all_content_types:
                        try:
                            image_content_data[content_type] = anchore_engine.common.helpers.extract_analyzer_content(image_data, content_type, manifest=manifest)
                        except Exception as err:
                            logger.warn("ERR: {}".format(err))
                            image_content_data[content_type] = {}

                    if image_content_data:
                        logger.debug("adding image content data to archive")
                        rc = catalog_client.put_document('image_content_data', image_digest, image_content_data)

                        logger.debug("adding image analysis data to image_record")
                        anchore_engine.common.helpers.update_image_record_with_analysis_data(image_record, image_data)

                except Exception as err:
                    import traceback
                    traceback.print_exc()
                    logger.warn("could not store image content metadata to archive - exception: " + str(err))

                logger.info("adding image to policy engine: account={} imageId={} imageDigest={}".format(account, imageId, image_digest))
                try:
                    if not imageId:
                        raise Exception("cannot add image to policy engine without an imageId")

                    # localconfig = anchore_engine.configuration.localconfig.get_config()
                    verify = localconfig['internal_ssl_verify']

                    pe_client = internal_client_for(PolicyEngineClient, account)

                    try:
                        logger.debug("clearing any existing image record in policy engine: {} / {} / {}".format(account, imageId, image_digest))
                        rc = pe_client.delete_image(user_id=account, image_id=imageId)
                    except Exception as err:
                        logger.warn("exception on pre-delete - exception: " + str(err))

                    client_success = False
                    last_exception = None
                    for retry_wait in [1, 3, 5, 0]:
                        try:
                            logger.debug('loading image into policy engine: {} / {} / {}'.format(account, imageId, image_digest))
                            image_analysis_fetch_url = 'catalog://' + str(account) + '/analysis_data/' + str(image_digest)
                            logger.debug("policy engine request: " + image_analysis_fetch_url)
                            resp = pe_client.ingress_image(account, imageId, image_analysis_fetch_url)
                            logger.debug("policy engine image add response: " + str(resp))
                            client_success = True
                            break
                        except Exception as e:
                            logger.warn("attempt failed, will retry - exception: {}".format(e))
                            last_exception = e
                            time.sleep(retry_wait)
                    if not client_success:
                        raise last_exception

                except Exception as err:
                    newerr = PolicyEngineClientError(msg='Adding image to policy-engine failed', cause=str(err))
                    event = events.PolicyEngineLoadAnalysisFailed(user_id=account, image_digest=image_digest, error=newerr.to_dict())
                    analysis_events.append(event)
                    raise newerr

                logger.debug("updating image catalog record analysis_status")

                last_analysis_status = image_record['analysis_status']
                image_record['analysis_status'] = anchore_engine.subsys.taskstate.complete_state('analyze')
                image_record['analyzed_at'] = int(time.time())
                rc = catalog_client.update_image(image_digest, image_record)

                try:
                    notify_analysis_complete(image_record, last_analysis_status)
                except Exception as err:
                    logger.warn("failed to enqueue notification on image analysis state update - exception: " + str(err))

            else:
                err = CatalogClientError(msg='Failed to upload analysis data to catalog', cause='Invalid response from catalog API - {}'.format(str(rc)))
                event = events.SaveAnalysisFailed(user_id=account, image_digest=image_digest, error=err.to_dict())
                analysis_events.append(event)
                raise err

            logger.info("analysis complete: " + str(account) + " : " + str(image_digest))

            logger.spew("TIMING MARK1: " + str(int(time.time()) - timer))

            try:
                anchore_engine.subsys.metrics.counter_inc(name='anchore_analysis_success')
                run_time = float(time.time() - timer)

                anchore_engine.subsys.metrics.histogram_observe('anchore_analysis_time_seconds', run_time, buckets=ANALYSIS_TIME_SECONDS_BUCKETS, status="success")

            except Exception as err:
                logger.warn(str(err))
                pass

        except Exception as err:
            anchore_engine.subsys.metrics.counter_inc(name='anchore_analysis_error')
            run_time = float(time.time() - timer)
            logger.exception("problem analyzing image - exception: " + str(err))
            anchore_engine.subsys.metrics.histogram_observe('anchore_analysis_time_seconds', run_time, buckets=ANALYSIS_TIME_SECONDS_BUCKETS, status="fail")
            image_record['analysis_status'] = anchore_engine.subsys.taskstate.fault_state('analyze')
            image_record['image_status'] = anchore_engine.subsys.taskstate.fault_state('image_status')
            rc = catalog_client.update_image(image_digest, image_record)

            if account and image_digest:
                for image_detail in image_record['image_detail']:
                    fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
                    event = events.UserAnalyzeImageFailed(user_id=account, full_tag=fulltag, error=str(err))
                    analysis_events.append(event)
        finally:
            if analysis_events:
                for event in analysis_events:
                    try:
                        catalog_client.add_event(event)
                    except:
                        logger.error('Ignoring error sending event')

    except Exception as err:
        logger.warn("job processing bailed - exception: " + str(err))
        raise err

    return True


class ImageAnalysisTask(WorkerTask):
    """
    The actual analysis task
    """

    def __init__(self, message: AnalysisQueueMessage, layer_cache_enabled: bool = False):
        super().__init__()
        self.layer_cache_enabled = layer_cache_enabled
        self.message = message

    def execute(self):
        return process_analyzer_job(self.message, self.layer_cache_enabled)
