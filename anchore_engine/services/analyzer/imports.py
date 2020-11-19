import base64
import json
import time

from .tasks import WorkerTask
from anchore_engine.subsys import logger
from anchore_engine.common.schemas import ImportManifest, ImportQueueMessage, ValidationError, ImageMetadata
from anchore_engine.utils import timer, AnchoreException
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.analyzers.utils import merge_nested_dict
from anchore_engine.analyzers.syft import convert_syft_to_engine
from anchore_engine.services.analyzer.utils import update_analysis_complete, update_analysis_failed, update_analysis_started, emit_events
from anchore_engine.services.analyzer.analysis import notify_analysis_complete, analysis_failed_metrics, store_analysis_results, ANALYSIS_TIME_SECONDS_BUCKETS as IMPORT_TIME_SECONDS_BUCKETS
from anchore_engine.configuration import localconfig
from anchore_engine.subsys import metrics, events, taskstate
import anchore_engine.clients.localanchore_standalone


class InvalidImageStateException(Exception):
    pass


class MissingRequiredContentException(Exception):
    pass


def image_manifest_from_syft(syft_sbom):
    """

    Example sbom's "source" property:
    {
    ...
     "source": {
          "type": "image",
          "target": {
           "layers": [
            {
             "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
             "digest": "sha256:d0fe97fa8b8cefdffcef1d62b65aba51a6c87b6679628a2b50fc6a7a579f764c",
             "size": 69201311
            },
            {
             "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
             "digest": "sha256:f14cffae5c1add412127e0704008bb8e730773c0945345c9ea61b7e6eabea8e5",
             "size": 63622974
            },
            {
             "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
             "digest": "sha256:280ddd108a0a0ef53ed20d6715facc1cdd9497ef05cad03c3e5b73521a588511",
             "size": 1202
            },
            {
             "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
             "digest": "sha256:fe08d9d9f18556ca241f00b6efd6c7b25767463084e14c05da9e535c0782409c",
             "size": 1957
            },
            {
             "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
             "digest": "sha256:cdd1d8ebeb066bd40f9be824201afe18f0d4fe93b8462353921f0277c09e1289",
             "size": 1037
            }
           ],
           "size": 132828481,
           "digest": "sha256:f35646e83998b844c3f067e5a2cff84cdf0967627031aeda3042d78996b68d35",
           "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
           "tags": [
            "nginx:latest"
           ]
          }
         }
    }
    :param syft_sbom:
    :return:
    """
    return syft_sbom.get('source', {}).get('target')


# Copied and modified from the localanchore_standalone file's analyze_image()
def process_import(manifest, image_record, sbom, import_manifest: ImportManifest):
    # need all this

    analyzer_manifest = {} # Apparently not used
    image_id = import_manifest.local_image_id or import_manifest.digest
    layers = [] # TODO: fix this to use layers from syft if available
    familytree = []
    imageSize = import_manifest.metadata.size
    imageArch = import_manifest.metadata.platform.architecture
    docker_history = {}
    pullstring = None
    fulltag = None

    try:
        image_digest = image_record['imageDigest']
        if image_digest != import_manifest.digest:
            raise Exception('Image digest in import manifest does not match catalog record')

        dockerfile_mode = image_record.get('dockerfile_mode', '')

        image_detail = image_record['image_detail'][0]
        pullstring = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail['imageDigest']
        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
        imageId = image_detail['imageId']
        if image_detail['dockerfile']:
            dockerfile_contents = str(base64.decodebytes(image_detail['dockerfile'].encode('utf-8')), 'utf-8')
        else:
            dockerfile_contents = None

        # manifest_data = image_manifest_from_syft(syft_packages)
        # try:
        #     if manifest_data['schemaVersion'] == 1:
        #         docker_history, layers, dockerfile_contents, dockerfile_mode, imageArch = get_image_metadata_v1(staging_dirs, imageDigest, imageId, manifest_data, dockerfile_contents=dockerfile_contents, dockerfile_mode=dockerfile_mode)
        #     elif manifest_data['schemaVersion'] == 2:
        #         docker_history, layers, dockerfile_contents, dockerfile_mode, imageArch = get_image_metadata_v2(staging_dirs, imageDigest, imageId, manifest_data, dockerfile_contents=dockerfile_contents, dockerfile_mode=dockerfile_mode)
        #     else:
        #         raise ManifestSchemaVersionError(schema_version=manifest_data['schemaVersion'], pull_string=pullstring, tag=fulltag)
        # except ManifestSchemaVersionError:
        #     raise
        # except Exception as err:
        #     raise ManifestParseError(cause=err, pull_string=pullstring, tag=fulltag)

        timer = time.time()

        # Move data from the syft sbom into the analyzer output
        analyzer_report = {
            'analyzer_meta': {
                'analyzer_meta': {
                    'base': {
                        'DISTRO': sbom.get('distro', {}).get('name'),
                        'DISTROVERS': sbom.get('distro', {}).get('version'),
                        'LIKEDISTRO': sbom.get('distro', {}).get('idLIke', 'DEB') # TODO: fix me
                    }
                }
            }
        }

        try:
            syft_results = convert_syft_to_engine(sbom)
            merge_nested_dict(analyzer_report, syft_results)
        except Exception as err:
            raise anchore_engine.clients.localanchore_standalone.AnalyzerError(cause=err, pull_string=pullstring, tag=fulltag)
        logger.debug("timing: total analyzer time: {} - {}".format(pullstring, time.time() - timer))

        try:
            image_report = anchore_engine.clients.localanchore_standalone.generate_image_export(image_id, analyzer_report, imageSize, fulltag, docker_history, dockerfile_mode, dockerfile_contents, layers, familytree, imageArch, pullstring, analyzer_manifest)
            logger.debug('Dumping image report: {}'.format(image_report))
        except Exception as err:
            raise anchore_engine.clients.localanchore_standalone.AnalysisReportGenerationError(cause=err, pull_string=pullstring, tag=fulltag)

    except AnchoreException:
        raise
    except Exception as err:
        raise anchore_engine.clients.localanchore_standalone.AnalysisError(cause=err, pull_string=pullstring, tag=fulltag, msg='failed to download, unpack, analyze, and generate image export')

    # if not imageDigest or not imageId or not manifest or not image_report:
    if not image_report:
        raise Exception("failed to analyze")

    return [image_report, manifest]


# def initialize_new_image(import_manifest: ImportManifest, client: CatalogClient):
#     """
#     Build new image record from scratch and save it in Catalog via API
#
#     :param import_manifest:
#     :param client:
#     :return:
#     """
#     resp = client.add_image(tag=import_manifest.tags[0] or None, digest=import_manifest.metadata.digest, annotations=import_manifest.annotations)
#     resp = client.update_image(imageDigest=import_manifest.metadata.digest, image_record=resp)
#     return resp


def get_content(account: str, operation_id: str, manifest: ImportManifest, content_type: str, client: CatalogClient):
    # NOTE: need to add the bucket and key into the message queue so that we don't have to share logic to fetch the content
    bucket = 'image_content_imports'  # wrong
    for digest in manifest.contents:
        key = '{}/{}/{}/{}'.format(account, operation_id, content_type, digest)
        content = client.get_document(bucket, key)
        if not content:
            raise MissingRequiredContentException('no content found in object store for content-type = %s and digest %s', content_type, digest)
        return content


# From analyzer
def import_image(operation_id, account, import_manifest: ImportManifest):
    timer = int(time.time())
    analysis_events = []

    config = localconfig.get_config()
    all_content_types = config.get('image_content_types', []) + config.get('image_metadata_types', [])
    image_digest = import_manifest.digest

    try:
        catalog_client = internal_client_for(CatalogClient, account)
        logger.info("Loading content from import")
        sbom = get_content(account, operation_id, import_manifest, 'packages', catalog_client)
        manifest = image_manifest_from_syft(sbom)

        # check to make sure image is still in DB
        catalog_client = internal_client_for(CatalogClient, account)
        try:
            image_record = catalog_client.get_image(image_digest)
            if not image_record:
                raise Exception("empty image record from catalog")
        except Exception as err:
            logger.warn("dequeued image cannot be fetched from catalog - skipping analysis (" + str(image_digest) + ") - exception: " + str(err))
            return True

        logger.info("image dequeued for imports: " + str(account) + " : " + str(image_digest))
        if image_record['analysis_status'] != taskstate.base_state('analyze'):
            logger.debug("dequeued image is not in base state - skipping analysis")
            return True

        try:
            logger.spew("TIMING MARK0: " + str(int(time.time()) - timer))

            last_analysis_status = image_record['analysis_status']
            image_record = update_analysis_started(catalog_client, image_digest, image_record)

            try:
                image_data, analysis_manifest = process_import(manifest, image_record, sbom, import_manifest)
            except AnchoreException as e:
                event = events.ImageAnalysisFailed(user_id=account, image_digest=image_digest, error=e.to_dict())
                analysis_events.append(event)
                raise

            logger.debug('Storing import result {}'.format(image_data))
            # Save the results to the upstream components and data stores
            store_analysis_results(account, image_digest, image_record, image_data, manifest, analysis_events, all_content_types)

            logger.debug("updating image catalog record analysis_status")
            last_analysis_status = image_record['analysis_status']
            image_record = update_analysis_complete(catalog_client, image_digest, image_record)

            try:
                notify_analysis_complete(image_record, last_analysis_status)
            except Exception as err:
                logger.warn("failed to enqueue notification on image analysis state update - exception: " + str(err))

            logger.info("analysis complete: " + str(account) + " : " + str(image_digest))
            logger.spew("TIMING MARK1: " + str(int(time.time()) - timer))

            try:
                metrics.counter_inc(name='anchore_analysis_success')
                run_time = float(time.time() - timer)

                metrics.histogram_observe('anchore_analysis_time_seconds', run_time, buckets=IMPORT_TIME_SECONDS_BUCKETS, status="success")

            except Exception as err:
                logger.warn(str(err))
                pass

        except Exception as err:
            run_time = float(time.time() - timer)
            logger.exception("problem analyzing image - exception: " + str(err))
            analysis_failed_metrics(run_time)

            # Transition the image record to failure status
            image_record = update_analysis_failed(catalog_client, image_digest, image_record)

            if account and image_digest:
                for image_detail in image_record['image_detail']:
                    fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
                    event = events.UserAnalyzeImageFailed(user_id=account, full_tag=fulltag, error=str(err))
                    analysis_events.append(event)
        finally:
            if analysis_events:
                emit_events(catalog_client, analysis_events)

    except Exception as err:
        logger.warn("job processing bailed - exception: " + str(err))
        raise err

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
        import_image(self.message.manifest.operation_uuid, self.account, self.message.manifest)
        logger.info('Import task %s complete', self.task_id)


def is_import_message(payload_json: dict) -> bool:
    try:
        return ImportQueueMessage.from_json(payload_json) is not None
    except ValidationError:
        return False
