import pytest

from anchore_engine.services.analyzer.imports import is_import_message

message_matrix = [
    ({
        'userId': 'account1',
        'imageDigest': 'sha256:abc123def456',
        'manifest': {
            'metadata': {
                'layers': None,
                'size': 0,
                'platform': None
            },
            'tags': ['sometag'],
            'contents': {
                'packages': 'sha256:abc',
                'manifest': 'sha256:cdef',
                'dockerfile': 'sha256:123abc'
            },
            'digest': 'sha256:abc123def456',
            'parent_digest': 'sha256:abc123def456',
            'local_image_id': 'abc123',
            'operation_uuid': '123-123-123'
        },
        'parent_manifest': None,
     }, True),
    ({
        'userId': 'account1',
        'imageDigest': 'sha256:abc',
        'manifest': "",
        'parent_manifest': ""
     }, False),
]

@pytest.mark.parametrize(("message", "is_import"), message_matrix)
def test_is_import_message(message: dict, is_import: bool):
    assert is_import_message(message) == is_import
