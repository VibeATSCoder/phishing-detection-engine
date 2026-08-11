import numpy as np

from persianphish_detector.models.tcn import BYTE_OFFSET, TCN_INPUT_CONTRACT, encode_url


def _decoded_prefix(encoded: np.ndarray) -> bytes:
    values = encoded[encoded != 0] - BYTE_OFFSET
    return bytes(values.astype(np.uint8).tolist())


def test_tcn_encodes_only_the_normalized_hostname_for_long_urls():
    short = encode_url("https://www.google.com/")
    long = encode_url("https://www.google.com/" + "/x" * 2_000 + "?token=abcdef")

    assert TCN_INPUT_CONTRACT == "normalized_hostname_only_v1"
    assert np.array_equal(short, long)
    assert _decoded_prefix(long) == b"www.google.com"
