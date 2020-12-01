import base64
import json
import time

from .tasks import WorkerTask
from anchore_engine.subsys import logger
from anchore_engine.common.schemas import (
    ImportManifest,
    ImportQueueMessage,
    ValidationError,
    ImageMetadata,
    ContentTypeDigests,
)
from anchore_engine.utils import timer, AnchoreException
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.analyzers.utils import merge_nested_dict
from anchore_engine.analyzers.syft import convert_syft_to_engine
from anchore_engine.services.analyzer.utils import (
    update_analysis_complete,
    update_analysis_failed,
    update_analysis_started,
    emit_events,
)
from anchore_engine.services.analyzer.analysis import (
    notify_analysis_complete,
    analysis_failed_metrics,
    store_analysis_results,
    ANALYSIS_TIME_SECONDS_BUCKETS as IMPORT_TIME_SECONDS_BUCKETS,
)
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
            "userInput": "nginx:latest",
            "scope": "Squashed",
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
        },
        "distro": {
          "name": "debian",
          "version": "10",
          "idLike": ""
        },
        "descriptor": {
          "name": "syft",
          "version": "0.8.0"
      }
    }
    :param syft_sbom:
    :return:
    """
    return syft_sbom.get("source", {}).get("target")


# Copied and modified from the localanchore_standalone file's analyze_image()
def process_import(
    guessed_manifest: dict,
    image_record: dict,
    sbom: dict,
    import_manifest: ImportManifest,
):
    """

    :param guessed_manifest:
    :param image_record:
    :param sbom: map of content type to manifest (e.g. {'packages': {....}, 'dockerfile': '....'}
    :param import_manifest:
    :return:
    """

    # need all this
    analyzer_manifest = {}  # Apparently not used
    image_id = import_manifest.local_image_id or import_manifest.digest
    layers = (
        []
    )  # TODO: fix this to use layers from 'source' element of the packages sbom?
    familytree = []
    image_size = import_manifest.metadata.size
    image_arch = import_manifest.metadata.platform.architecture
    docker_history = {}
    pullstring = None
    fulltag = None

    syft_packages = sbom.get("packages")
    dockerfile = sbom.get("dockerfile")
    manifest = sbom.get("manifest", guessed_manifest)


    try:
        image_digest = image_record["imageDigest"]
        if image_digest != import_manifest.digest:
            raise Exception(
                "Image digest in import manifest does not match catalog record"
            )

        dockerfile_mode = image_record.get("dockerfile_mode", "")

        image_detail = image_record["image_detail"][0]
        pullstring = (
            image_detail["registry"]
            + "/"
            + image_detail["repo"]
            + "@"
            + image_detail["imageDigest"]
        )
        fulltag = (
            image_detail["registry"]
            + "/"
            + image_detail["repo"]
            + ":"
            + image_detail["tag"]
        )

        # TODO: use temp/spool for content downloads and composition of result.
        # Have updated the API spec and obj to have multiple content types, use those. Not working yet.
        # Need to update the API controllers to handle the manifest and dockerfile contents

        # if image_detail['dockerfile']:
        #     dockerfile_contents = str(base64.decodebytes(image_detail['dockerfile'].encode('utf-8')), 'utf-8')
        # else:
        #     dockerfile_contents = None

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
            "analyzer_meta": {
                "analyzer_meta": {
                    "base": {
                        "DISTRO": syft_packages.get("distro", {}).get("name"),
                        "DISTROVERS": syft_packages.get("distro", {}).get("version"),
                        "LIKEDISTRO": syft_packages.get("distro", {}).get("idLike"),
                    }
                }
            }
        }

        try:
            syft_results = convert_syft_to_engine(syft_packages)
            merge_nested_dict(analyzer_report, syft_results)
        except Exception as err:
            raise anchore_engine.clients.localanchore_standalone.AnalyzerError(
                cause=err, pull_string=pullstring, tag=fulltag
            )
        logger.debug(
            "timing: total analyzer time: {} - {}".format(
                pullstring, time.time() - timer
            )
        )

        try:
            image_report = (
                anchore_engine.clients.localanchore_standalone.generate_image_export(
                    image_id,
                    analyzer_report,
                    image_size,
                    fulltag,
                    docker_history,
                    dockerfile_mode,
                    dockerfile,
                    layers,
                    familytree,
                    image_arch,
                    pullstring,
                    analyzer_manifest,
                )
            )
            logger.debug("Dumping image report: {}".format(image_report))
        except Exception as err:
            raise anchore_engine.clients.localanchore_standalone.AnalysisReportGenerationError(
                cause=err, pull_string=pullstring, tag=fulltag
            )

    except AnchoreException:
        raise
    except Exception as err:
        raise anchore_engine.clients.localanchore_standalone.AnalysisError(
            cause=err,
            pull_string=pullstring,
            tag=fulltag,
            msg="failed to download, unpack, analyze, and generate image export",
        )

    # if not imageDigest or not imageId or not manifest or not image_report:
    if not image_report:
        raise Exception("failed to analyze")

    return [image_report, manifest]


def get_content(
    account: str, operation_id: str, manifest: ImportManifest, client: CatalogClient
) -> dict:
    # NOTE: need to add the bucket and key into the message queue so that we don't have to share logic to fetch the content
    bucket = "image_content_imports"  # wrong
    content_map = {}
    if manifest.contents.packages:
        key = "{}/{}/{}/{}".format(
            account, operation_id, "packages", manifest.contents.packages
        )
        content_map["packages"] = json.loads(client.get_document(bucket, key))

    if manifest.contents.dockerfile:
        key = "{}/{}/{}/{}".format(
            account, operation_id, "dockerfile", manifest.contents.dockerfile
        )
        content_map["dockerfile"] = client.get_document(bucket, key)

    if manifest.contents.manifest:
        key = "{}/{}/{}/{}".format(
            account, operation_id, "manifest", manifest.contents.manifest
        )
        content_map["manifest"] = client.get_document(bucket, key)

    if manifest.contents.parent_manifest:
        key = "{}/{}/{}/{}".format(
            account, operation_id, "parent_manifest", manifest.contents.parent_manifest
        )
        content_map["parent_manifest"] = client.get_document(bucket, key)

    return content_map


def import_image(operation_id, account, import_manifest: ImportManifest):
    """
    The main thread of exec for importing an image

    :param operation_id:
    :param account:
    :param import_manifest:
    :return:
    """
    timer = int(time.time())
    analysis_events = []

    config = localconfig.get_config()
    all_content_types = config.get("image_content_types", []) + config.get(
        "image_metadata_types", []
    )
    image_digest = import_manifest.digest

    try:
        catalog_client = internal_client_for(CatalogClient, account)

        logger.info("Loading content from import")
        sbom_map = get_content(account, operation_id, import_manifest, catalog_client)

        logger.info("SBOM Map: {}".format(sbom_map.keys()))
        manifest = image_manifest_from_syft(sbom_map.get("packages", {}))

        # check to make sure image is still in DB
        catalog_client = internal_client_for(CatalogClient, account)
        try:
            image_record = catalog_client.get_image(image_digest)
            if not image_record:
                raise Exception("empty image record from catalog")
        except Exception as err:
            logger.debug_exception("Could not get image record")
            logger.warn(
                "dequeued image cannot be fetched from catalog - skipping analysis ("
                + str(image_digest)
                + ") - exception: "
                + str(err)
            )
            return True

        if image_record["analysis_status"] != taskstate.base_state("analyze"):
            logger.info(
                "dequeued image to import is not in base 'not_analyzed' state - skipping import"
            )
            return True

        try:
            last_analysis_status = image_record["analysis_status"]
            image_record = update_analysis_started(
                catalog_client, image_digest, image_record
            )

            try:
                logger.info("processing image import data")
                image_data, analysis_manifest = process_import(
                    manifest, image_record, sbom_map, import_manifest
                )
            except AnchoreException as e:
                event = events.ImageAnalysisFailed(
                    user_id=account, image_digest=image_digest, error=e.to_dict()
                )
                analysis_events.append(event)
                raise

            # Save the results to the upstream components and data stores
            logger.info("storing import result")
            store_analysis_results(
                account,
                image_digest,
                image_record,
                image_data,
                manifest,
                analysis_events,
                all_content_types,
            )

            logger.info("updating image catalog record analysis_status")
            last_analysis_status = image_record["analysis_status"]
            image_record = update_analysis_complete(
                catalog_client, image_digest, image_record
            )

            try:
                notify_analysis_complete(image_record, last_analysis_status)
            except Exception as err:
                logger.warn(
                    "failed to enqueue notification on image analysis state update - exception: "
                    + str(err)
                )

            logger.info(
                "analysis complete: " + str(account) + " : " + str(image_digest)
            )

            try:
                metrics.counter_inc(name="anchore_import_success")
                run_time = float(time.time() - timer)

                metrics.histogram_observe(
                    "anchore_import_time_seconds",
                    run_time,
                    buckets=IMPORT_TIME_SECONDS_BUCKETS,
                    status="success",
                )

            except Exception as err:
                logger.warn(str(err))

        except Exception as err:
            run_time = float(time.time() - timer)
            logger.exception("problem importing image - exception: " + str(err))
            analysis_failed_metrics(run_time)

            # Transition the image record to failure status
            image_record = update_analysis_failed(
                catalog_client, image_digest, image_record
            )

            if account and image_digest:
                for image_detail in image_record["image_detail"]:
                    fulltag = (
                        image_detail["registry"]
                        + "/"
                        + image_detail["repo"]
                        + ":"
                        + image_detail["tag"]
                    )
                    event = events.UserAnalyzeImageFailed(
                        user_id=account, full_tag=fulltag, error=str(err)
                    )
                    analysis_events.append(event)
        finally:
            if analysis_events:
                emit_events(catalog_client, analysis_events)

    except Exception as err:
        logger.debug_exception("Could not import image")
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
        logger.info(
            "Executing import task. Account = %s, Id = %s", self.account, self.task_id
        )
        import_image(
            self.message.manifest.operation_uuid, self.account, self.message.manifest
        )
        logger.info("Import task %s complete", self.task_id)


def is_import_message(payload_json: dict) -> bool:
    try:
        return ImportQueueMessage.from_json(payload_json) is not None
    except ValidationError:
        return False
