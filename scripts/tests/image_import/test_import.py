#!/usr/bin/env python3

"""
Simple example of an import flow of data output from `syft docker:nginx --output json` into Anchore. Uses syft v0.8.0 output.
"""

import sys
import requests
import json
import base64


def check_response(resp: requests.Response) -> dict:
    print("Got response: {}".format(resp.status_code))
    print("Payload: {}".format(resp.json()))
    if resp.status_code != 200:
        sys.exit(1)

    resp_payload = resp.json()
    return resp_payload


# The input file with the syft output sbom
syft_package_sbom = sys.argv[1]
dockerfile = sys.argv[2]
manifest = sys.argv[3] if len(sys.argv) > 3 else None
parent_manifest = sys.argv[4] if len(sys.argv) > 4 else None
JSON_HEADER = {"Content-Type": "application/json"}

# Defaults... don"t use these
AUTHC = ("admin", "foobar")

# NOTE: in these examples we load from the file as bytes arrays instead of json objects to ensure that the digest computation matches and
# isn't impacted by any python re-ordering of keys or adding/removing whitespace. This should enable the output of `sha256sum <file>` to match the digests returned during this test

if not syft_package_sbom:
    raise Exception("Must have valid input file as arg 1")
else:
    with open(syft_package_sbom) as f:
        sbom_content = bytes(f.read(), "utf-8")

    # Parse into json to extract some info
    parsed = json.loads(str(sbom_content, 'utf-8'))
    digest = parsed['source']['target']['digest'] # This is the image id, use it as digest since syft doesn't get a digest from a registry
    local_image_id = parsed['source']['target']['digest']

    print("Loaded content from file: {}".format(syft_package_sbom))

    # Step 1: Get a new operation uuid to use for correlating the data in the upload process
    print("Creating import operation")
    resp = requests.post("http://localhost/imports/images", auth=AUTHC)

    # There are other fields present, such as "expires_at" timestamp, but all we need to proceed is the operation"s uuid.
    operation_id = check_response(resp).get("uuid")

    # Step 2: Upload content (in the future there will likely be more than one content-type during this phase (e.g. FS metadata, content searches etc)
    print("Uploading syft package sbom")
    resp = requests.post("http://localhost/imports/images/{}/packages".format(operation_id), data=sbom_content, auth=AUTHC, headers=JSON_HEADER)
    packages_digest = check_response(resp).get("digest")

if dockerfile:
    with open(dockerfile) as f:
        dockerfile_content = bytes(f.read(), "utf-8")  # str(base64.standard_b64encode(bytes(f.read(), "utf-8")), "utf-8")
    print("Loaded dockerfile content from {}".format(dockerfile))

    print("Uploading dockerfile")
    resp = requests.post("http://localhost/imports/images/{}/dockerfile".format(operation_id), data=dockerfile_content, auth=AUTHC)
    dockerfile_digest = check_response(resp).get("digest")
else:
    dockerfile_digest = None

if manifest:
    with open(manifest) as f:
        manifest_content = bytes(f.read(), "utf-8")
    print("Loaded manifest content from {}".format(manifest))

    print("Uploading image manifest")
    resp = requests.post("http://localhost/imports/images/{}/manifest".format(operation_id), data=dockerfile_content, auth=AUTHC, headers=JSON_HEADER)
    manifest_digest = check_response(resp).get("digest")
else:
    manifest_digest = None

if parent_manifest:
    with open(parent_manifest) as f:
        parent_manifest_content = bytes(f.read(), "utf-8")
    print("Loaded parent_manifest content from {}".format(parent_manifest))

    print("Uploading parent manifest (manifest list")
    resp = requests.post("http://localhost/imports/images/{}/parent_manifest".format(operation_id), data=parent_manifest_content, auth=AUTHC, headers=JSON_HEADER)

    print("Got response: {}".format(resp.status_code))
    print("Payload: {}".format(resp.json()))
    if resp.status_code != 200:
        sys.exit(1)

    # Get the digest from the response
    resp_payload = resp.json()
    parent_manifest_digest = resp_payload["digest"]
else:
    parent_manifest_digest = None

# Construct the type-to-digest map
contents = {
    "packages": packages_digest,
    "dockerfile": dockerfile_digest,
    "manifest": manifest_digest,
    "parent_manifest": parent_manifest_digest
}

# Step 3: Complete the import by generating the import manifest which includes the conetnt reference as well as other metadata
# for the image such as digest, annotations, etc
add_payload = {
    "source": {
        "import": {
            "digest": digest,
            #"parent_digest": None,
            "local_image_id": local_image_id,
            "metadata": {
                "layers": [{"digest": "sha256:cdef", "size": 10000, "location": ""}],
                "platform": {
                    "os": "linux",
                    "architecture": "amd64"
                },
                "size": parsed['source']['target']['size']
            },
            "contents": contents,
            "tags": parsed['source']['target']['tags'],
            "operation_uuid": operation_id
        }
    }
}

print("Adding image/finalizing")
resp = requests.post("http://localhost/images", json=add_payload, auth=AUTHC)
result = check_response(resp)

# Step 5: Check the /images endpoint to see that the record was added and is in not_analyzed and will transition to "analyzing" and then "analyzed" once import is complete"
print("Checking image list")
resp = requests.get("http://localhost/images/{digest}".format(digest=digest), auth=AUTHC)
images = check_response(resp)

# Check for finished
print("Completed successfully!")
