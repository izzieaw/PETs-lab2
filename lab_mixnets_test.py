#####################################################
# COMP0061 Privacy Enhancing Technologies -- Lab on Mix Systems
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ pytest -v


import sys
import pytest
from os import urandom
from pytest import raises
from Cryptodome.PublicKey import _point

curves = _point._curves

from lab_mixnets import *


#####################################################
# TASK 1 -- Ensure libraries are installed on the system.
#           Ensure the lab code can be imported.

@pytest.mark.task1
def test_libs_present():
    """
    Check Cryptodome and pytest are imported
    """
    assert "Cryptodome" in sys.modules
    assert "pytest" in sys.modules


@pytest.mark.task1
def test_code_present():
    """
    Check lab_mixnets is imported
    """
    assert "lab_mixnets" in sys.modules


#####################################################
# TASK 2 -- Build a 1-hop mix client.


# What is a test fixture?
# http://pytest.org/latest/fixture.html

@pytest.fixture
def encode_Alice_message():
    """
    Encode a single message
    """
    group = curves["secp224r1"]
    o = group.order
    g = group.G

    private_key = Integer.random_range(min_inclusive=1, max_exclusive=o)
    public_key = g * private_key

    m1 = mix_client_one_hop(group, public_key, b"Alice", b"Dear Alice,\nHello!\nBob")
    return private_key, m1


@pytest.mark.task2
def test_Alice_message_overlong():
    """
    Test overlong address or message
    """
    group = curves["secp224r1"]
    o = group.order
    g = group.G

    private_key = Integer.random_range(min_inclusive=1, max_exclusive=o)
    public_key = g * private_key

    with raises(AssertionError):
        mix_client_one_hop(group, public_key, urandom(1000), b"Dear Alice,\nHello!\nBob")

    with raises(AssertionError):
        mix_client_one_hop(group, public_key, b"Alice", urandom(10000))


@pytest.mark.task2
def test_simple_client_part_type(encode_Alice_message):
    private_key, Alice_message = encode_Alice_message

    # Ensure the client encodes a NamedTuple of type "OneHopMixMessage"
    assert isinstance(Alice_message, tuple)
    assert len(Alice_message) == 4
    assert Alice_message.ec_public_key
    assert Alice_message.hmac
    assert Alice_message.address
    assert Alice_message.message


@pytest.mark.task2
def test_simple_client_decode(encode_Alice_message):
    private_key, Alice_message = encode_Alice_message

    # Ensure the mix can decode the message correctly
    res1 = mix_server_one_hop(private_key, [Alice_message])

    assert len(res1) == 1
    assert res1[0] == (b"Alice", b"Dear Alice,\nHello!\nBob")


@pytest.mark.task2
def test_simple_client_decode_many():
    group = curves["secp224r1"]
    o = group.order
    g = group.G

    private_key = Integer.random_range(min_inclusive=1, max_exclusive=o)
    public_key = g * private_key

    messages = []
    expected = []
    for _ in range(100):
        m_input = (urandom(256), urandom(1000))
        expected += [m_input]
        m = mix_client_one_hop(group, public_key, *m_input)
        messages += [m]

    # Ensure the mix can decode the message correctly
    result = mix_server_one_hop(private_key, messages)

    assert len(result) == 100
    assert result == sorted(expected)


###################################
# TASK 3 -- A multi-hop mix

@pytest.mark.task3
def test_Alice_encode_1_hop():
    """
    Test sending a multi-hop message through 1-hop
    """
    group = curves["secp224r1"]
    o = group.order
    g = group.G

    private_key = Integer.random_range(min_inclusive=1, max_exclusive=o)
    public_key = g * private_key

    address = b"Alice"
    message = b"Dear Alice,\nHello!\nBob"

    m1 = mix_client_n_hop(group, [public_key], address, message)
    out = mix_server_n_hop(private_key, [m1], final=True)

    assert out == [(address, message)]


@pytest.mark.task3
def test_Alice_encode_3_hop():
    """
    Test sending a multi-hop message through 1-hop
    """
    group = curves["secp224r1"]
    o = group.order
    g = group.G

    private_keys = [Integer.random_range(min_inclusive=1, max_exclusive=o) for _ in range(3)]
    public_keys = [g * private_key for private_key in private_keys]

    address = b"Alice"
    message = b"Dear Alice,\nHello!\nBob"

    m1 = mix_client_n_hop(group, public_keys, address, message)
    out = mix_server_n_hop(private_keys[0], [m1])
    out = mix_server_n_hop(private_keys[1], out)
    out = mix_server_n_hop(private_keys[2], out, final=True)

    assert out == [(address, message)]


###########################################
# TASK 4 -- Simple traffic analysis / SDA

import random


@pytest.mark.task4
def test_trace_static():
    # A fixed set and number of friends
    exceptions = []
    for _ in range(100):
        try:
            trace = generate_trace(100, 10, 1000, [1, 2, 3])
            friends = analyze_trace(trace, 3)
            assert len(friends) == 3
            assert sorted(friends) == [1, 2, 3]
        except AssertionError as err:
            exceptions.append(err)
    if len(exceptions) > 33:
        message = f"Failed to correctly identify friends in {len(exceptions)}% test runs"
        try:
            exception = ExceptionGroup
        except NameError:
            exception = Exception
        raise exception(message, exceptions)


@pytest.mark.task4
def test_trace_variable():
    # A random number of friends and random contacts
    random.seed('PETS')
    exceptions = []
    for _ in range(1000):
        try:
            friend_number = random.choice(range(1, 10))
            friends = random.sample(range(100), friend_number)

            trace = generate_trace(100, 10, 1000, friends)
            TA_friends = analyze_trace(trace, len(friends))
            assert len(TA_friends) == len(friends)
            assert sorted(TA_friends) == sorted(friends)
        except AssertionError as err:
            exceptions.append(err)
    if len(exceptions) > 333:
        message = f"Failed to correctly identify friends in {len(exceptions) / 10}% test runs"
        try:
            exception = ExceptionGroup
        except NameError:
            exception = Exception
        raise exception(message, exceptions)
