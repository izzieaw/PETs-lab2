#####################################################
# COMP0061 Privacy Enhancing Technologies -- Lab on Mix Systems
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ pytest -v

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.


from struct import pack, unpack
from typing import NamedTuple
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA512
from Cryptodome.Math.Numbers import Integer
from Cryptodome.PublicKey import ECC, _curve

Curve = _curve._Curve
PrivKey = Integer
PubKey = ECC.EccPoint

def aes_ctr_enc_dec(key, iv, message):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption. 
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in fact the same operations.
    """
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    output = cipher.encrypt(message)

    return output


def _point_to_bytes(p: ECC.EccPoint) -> bytes:
    x, y = p.xy
    return x.to_bytes() + y.to_bytes()

#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
#

# This is the type of messages destined for the one-hop mix
OneHopMixMessage = NamedTuple('OneHopMixMessage', [('ec_public_key', PubKey),
                                                   ('hmac', bytes),
                                                   ('address', bytes),
                                                   ('message', bytes)])


def mix_server_one_hop(private_key: PrivKey, message_list: list[OneHopMixMessage]) -> list[tuple[bytes, bytes]]:
    """ Implements the decoding for a simple one-hop mix. 

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned

    """
    out_queue = []

    # Process all messages
    for msg in message_list:

        # Check elements and lengths
        if not len(msg.hmac) == 20 or \
            not len(msg.address) == 258 or \
            not len(msg.message) == 1002:
            raise Exception("Malformed input message")

        # First get a shared key
        shared_element = msg.ec_public_key * private_key
        key_material = SHA512.new(_point_to_bytes(shared_element)).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Check the HMAC
        h = HMAC.new(key=hmac_key, digestmod=SHA512)
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not msg.hmac == expected_mac[:20]:
            raise Exception("HMAC check failure")

        # Decrypt the address and the message
        iv = b"\x00" * 8

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)


def mix_client_one_hop(group: Curve, public_key: PubKey, address: bytes, message: bytes) -> OneHopMixMessage:
    """
    Encode a message to travel through a single mix with a set public key.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an HMAC (20 bytes), an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).
    """
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    # Generate a fresh public key
    private_key = Integer.random_range(min_inclusive=1, max_exclusive=group.order)
    client_public_key = group.G * private_key

    # First get a shared key
    shared_element = public_key * private_key # mix pk * msg sk
    key_material = SHA512.new(_point_to_bytes(shared_element)).digest()

    # Use different parts of the shared key for different operations
    hmac_key = key_material[:16]
    address_key = key_material[16:32]
    message_key = key_material[32:48]

    # Encrypt the address and the message
    iv = b"\x00" * 8

    address_cipher = aes_ctr_enc_dec(address_key, iv, address)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message)

    # Calculate HMAC
    h = HMAC.new(key=hmac_key, digestmod=SHA512)
    h.update(address)
    h.update(message)
    expected_mac = h.digest()
    expected_mac = expected_mac[:20]

    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)


#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
#

# This is the type of messages destined for the n-hop mix
NHopMixMessage = NamedTuple('NHopMixMessage', [('ec_public_key', PubKey),
                                               ('hmacs', list[bytes]),
                                               ('address', bytes),
                                               ('message', bytes)])


def mix_server_n_hop(private_key: PrivKey, message_list: list[NHopMixMessage], final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn:
        - it derives a shared key (using its private_key),
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message.
    """
    out_queue = []

    # Process all messages
    for msg in message_list:
        # Check elements and lengths
        if not isinstance(msg.hmacs, list) or \
                not len(msg.hmacs[0]) == 20 or \
                not len(msg.address) == 258 or \
                not len(msg.message) == 1002:
            raise Exception("Malformed input message")

        # First get a shared key
        shared_element = msg.ec_public_key * private_key
        key_material = SHA512.new(_point_to_bytes(shared_element)).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Integer.from_bytes(key_material[48:])
        new_ec_public_key =  msg.ec_public_key * blinding_factor

        # Check the HMAC
        h = HMAC.new(key=hmac_key, digestmod=SHA512)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()

        if not msg.hmacs[0] == expected_mac[:20]:
            raise Exception("HMAC check failure")

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H6s", i, b"\x00" * 6)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00" * 8

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(group: Curve, public_keys: list[PubKey], address: bytes, message: bytes) -> NHopMixMessage:
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).

    """
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    # Generate a fresh public key
    private_key = Integer.random_range(min_inclusive=1, max_exclusive=group.order)
    client_public_key = group.G * private_key
    # TODO: ADD CODE HERE
    ...
    address_cipher = ...
    message_cipher = ...
    hmacs = ...
    return NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher)


#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces the objective is to output an ordered list of likely `friends` of a target user.

import random

Trace = list[tuple[list[int], list[int]]]


def generate_trace(number_of_users: int, threshold_size: int, number_of_rounds: int, targets_friends: list[int]) -> Trace:
    """ Generate a simulated trace of traffic. """
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    # Generate traces in which Alice (user 0) is not sending
    for _ in range(9 * number_of_rounds // 10):
        senders = sorted(random.sample(others, threshold_size))
        receivers = sorted(random.sample(all_users, threshold_size))

        trace += [(senders, receivers)]

    # Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 10):
        senders = sorted([0] + random.sample(others, threshold_size - 1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample(all_users, threshold_size - 1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


from collections import Counter


def analyze_trace(trace: Trace, target_number_of_friends: int, target: int = 0) -> list[int]:
    """
    Given a trace of traffic, and a given number of friends,
    return the list of receiver identifiers that are the most likely
    friends of the target.
    """

    # TODO: ADD CODE HERE
    ...
    friends = ...

    return friends


#####################################################
# TASK Q1 - Answer the following question:
#
# The mix packet format you worked on uses AES-CTR with an IV set to all zeros.
# Explain whether this is a security concern and justify your answer.

""" TODO: Your answer HERE """

#####################################################
# TASK Q2 - Answer the following question:
#
# What assumptions does your implementation of the Statistical Disclosure Attack makes about the distribution of traffic
# from non-target senders to receivers?
# Is the correctness of the result returned dependent on this background distribution?

""" TODO: Your answer HERE """
