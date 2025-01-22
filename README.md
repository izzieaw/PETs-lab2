[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/XXR9KHA2)
[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=17811397)
[<img alt="points bar" align="right" height="36" src="../../blob/badges/.github/badges/points-bar.svg" /> <img alt="Workflow status" align="right" src="../../workflows/Autograding/badge.svg" />](../../actions/workflows/classroom.yml)

# COMP0061 -- Privacy Enhancing Technologies -- Lab on Mix Systems

This lab will introduce the basics of Engineering Mix Systems and Traffic Analysis.

### Structure of Labs

The structure of most of the labs will be similar: two Python files will be provided.

- The first is named `lab_X.py` and contains the structure of the code you need to complete.
- The second is named `lab_X_test.py` and contains unit tests (written for the Pytest library) that you may execute to
  partially check your answers.

Note that the tests passing is a necessary but not sufficient condition to fulfill each task. There are programs that
would make the tests pass that would still be invalid (or blatantly insecure) implementations.

The only dependency your Python code should have, besides Pytest and the standard library, is the Pycryptodome library.

The Pycryptodome documentation is [available on-line here](https://www.pycryptodome.org/src/introduction).

### Checking out code

Check out the code by using your preferred git client (e.g., git command line client, GitHub Desktop, Sourcetree).

**_Alternatively_**, you can use the GitHub Codespaces feature to check out and work on the code in the cloud.

### Setup

The intended environment for this lab is the Linux operating system with Python 3 installed.

#### Local virtual environment

To create a local virtual environment, activate the virtual environment, and install the dependencies needed for the
lab, run the following commands in the lab folder:

```shell
python3 -m venv .venv/
source .venv/bin/activate
pip3 install -r requirements.txt
```

On subsequent runs, you will only need to activate the virtualenv.

```shell
source .venv/bin/activate
```

To exit the virtual environment, run:

```shell
deactivate
```

The virtual environment is needed to run the unit tests locally.

#### Development containers

As an alternative to a local virtual environment, we provide the setup files for
[development containers](https://code.visualstudio.com/docs/remote/containers) which use
[Docker](https://docs.docker.com/get-docker/) to create a separate development environment for each repository and
install the required libraries. You don't need to know how to use Docker to use development containers. These are
supported by popular IDEs such as [Visual Studio Code](https://code.visualstudio.com/) and
[PyCharm](https://www.jetbrains.com/pycharm/).

#### GitHub Codespaces

Another alternative for running your code is to use GitHub Codespaces which use cloud-based development containers. On
GitHub, the "<> Code" button at the top right of the repository page will have a Codespaces tab. This allows you to
create a cloud-based environment to work on the assignment. You still need to use `git` to commit and push your work
when working in a codespace.

#### GitHub Classroom tests

The tests are the same as the ones that run as part of the GitHub Classroom automated marking system, so you can also
run the tests by simply committing and pushing your changes to GitHub, without the need for a local setup or even having
Python 3 installed.

### Working with unit tests

Unit tests are run from the command line by executing the command:

```sh
$ pytest -v
```

Note the `-v` flag toggles a more verbose output. If you wish to inspect the output of the full tests run you may pipe
this command to the `less` utility (execute `man less` for a full manual of the less utility):

```sh
$ pytest -v | less
```

You can also run a selection of tests associated with each task by adding the Pytest marker for each task to the Pytest
command:

```sh
$ pytest -v -m task1
```

The markers are defined in the test file and listed in `pytest.ini`.

You may also select tests to run based on their name using the `-k` flag. Have a look at the test file to find out the
function names of each test. For example the following command executes the very first test of Lab 1:

```sh
$ pytest -v -k test_libs_present
```

The full documentation of pytest is [available here](http://pytest.org/latest/).

### What you will have to submit

The deadline for all labs is at the end of term but labs will be progressively released throughout the term, as new
concepts are introduced. We encourage you to attempt labs as soon as they are made available and to use the dedicated
lab time to bring up any queries with the TAs.

Labs will be checked using GitHub Classroom, and the tests will be run each time you push any changes to the `main`
branch of your GitHub repository. The latest score from automarking should be shown in the Readme file. To see the test
runs, look at the Actions tab in your GitHub repository.

Make sure the submitted `lab_mixnets.py` file at least satisfies the tests, without the need for any external dependency
except the Python standard libraries and the Pycryptodome library. Only submissions prior to the GitHub Classroom
deadline will be marked, so make sure you push your code in time.

To re-iterate, the tests passing is a necessary but not sufficient condition to fulfill each task. All submissions will
be checked by TAs for correctness and your final marks are based on their assessment of your work.  
For full marks, make sure you have fully filled in any sections marked with `TODO` comments, including answering any
questions in the comments of the `lab_mixnets.py`.

## TASK 1 -- Check installation \[0.5 point\]

> Ensures that the key libraries have been loaded, and the code files are present. Nothing to do beyond ensuring this is
> the case.

## TASK 2 -- Build a simple 1-hop mix client \[1.5 point\]

> You are provided the code of the inner decoding function of a simple, one-hop mix server. Your task is to write a
> function that encodes a message to be sent through the mix.

## Hints:

- You can run the tests just for this task by executing:

  ```sh
  pytest -v -m task2
  ```

- Your objective is to complete the function `mix_client_one_hop`. This function takes as inputs a public key (an EC
  element) of the mix, an address and a message. It must then encode the message to be processed by the
  `mix_server_one_hop` in such a way that the mix will output a tuple of (address, message) to be routed to its final
  destination.

- The message type is a Python NamedTuple already defined for you as `OneHopMixMessage`. The function
  `mix_client_one_hop` must return an object of this type. Such an object may be created simply by calling:
  `python 	OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher) 	` where the
  `client_public_key` is an EC point, the expected Hmac is an Hmac of the `address_cipher` and `message_cipher`, and
  those are AES Counter mode (AES-CTR) ciphertexts of the encoded address and message.

- Study the function `mix_server_one_hop` that implements the one-hop mix. Take note of all the cryptographic operations
  and checked performed in order to process a message. You will have to ensure they decode your message correctly.

- The first element of a message is an ephemeral public key defined by the client (and the client knows its private
  part). The private key is used to derive a shared secret with the mix, using the mix public key. Study the code of the
  one-hop mix to examine the key derivation, and ensure your client mirrors it to generate messages that decode
  correctly.

- Study the code of the mix in `mix_server_one_hop` to determine the cryptographic operations necessary to encrypt
  correctly the address and message, as well as producing a valid Hmac. A helper function `aes_ctr_enc_dec` is provided
  to help you encrypt/decrypt using AES Counter mode. If you are not familiar with
  [AES Counter mode have a look online](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29).

- An Hmac is a cryptographic checksum that can be used to ensure parts of a message were generated by the holder of a
  shared secret key. If you are unsure of what a message authentication code does, do check the
  [HMAC primitive on wikipedia](http://en.wikipedia.org/wiki/Hash-based_message_authentication_code).

## TASK 3 -- Build an n-hop mix client. \[1.5 point\]

> In this exercise you will be required to encode a message to be relayed by a cascade of mixes. Each of the mixes has a
> public key, and the messages is passed to each of the mixes in order before being output.
>
> Your task here is to complete the `mix_client_n_hop` so that it encodes an address and message to be relayed by a
> sequence of mixes in order (the sequence is implicit, the order of their public keys is given.)

## Hints:

- You can run the tests just for this task by executing:

  ```sh
  pytest -v -m task3
  ```

- The key differences between the 1-hop mix and the n-hop mix message encoding relates to: (1) the use of a blinding
  factor to provide bit-wise unlikability of the public key associated with the message; (2) the inclusion of a sequence
  (list) of Hmacs as the second part of the mix message; (3) the decryption of the Hmacs (in addition to the address and
  message) at each step of mixing.

- The output of the function `mix_client_n_hop` should be an `NHopMixMessage`. The first element is a public key, the
  second is a list of Hmacs, the third is the encrypted address and the final one is the encrypted message. You can
  build such a structure using: `python 	NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher) 	`
- Study the mix operation in `mix_server_n_hop`. You will notice that the mix derives a shared key, and then uses it to
  check the first hmac in the list against the rest of the ciphertext. You must ensure your client encoding passes this
  test.

- Remember that messages are encoded in reverse order, so the last mix in the sequence is the first to be processed on
  the client-side.

- At each step of the mix, the server blinds the public key of the message by multiplying it with a blinding factor. As
  it travels through the mix, the blinding factor is accumulated in the public key. This ensures the public key is not
  linkable across mixes. Therefore, after the first mix, the shared key must contain not only the mix and client keys,
  but also an accumulated blinding factor. You must ensure that the client encoding mirrors this operation and produces
  the same shared key by applying the accumulated blinding factors to the mix keys on the client-side.
- Debugging tip - disabling the blinding factor in the n-hop server can help verify that the rest of the encoding is
  correct. Just remember to re-enable it before submitting your code, you will not get full marks without working
  blinding.

- This task is fiddly, and you are likely to see a number of Hmac verification failures. Do not lose hope:
  systematically dump the inputs to your Hmacs (using `print`) as well as the keys, to ensure the client and the servers
  hmac the same data under the same keys.

## TASK 4 -- Simple Traffic Analysis / Statistical Disclosure. \[1.5 point\]

> In this exercise you will be required to recover the social contacts of a target user, that is sending messages
> through an anonymity system (traffic analysis). A trace of traffic is provided to your function, as well as the number
> of social contacts of the target. You should return your best guess about whom the user 0 has sent messages to.

## Hints:

- You can run the tests just for this task by executing:

  ```sh
  pytest -v -m task4
  ```

- Chapter 9 of
  [Designing and attacking anonymous communication systems](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-594.pdf) by
  George Danezis covers statistical disclosure attacks on mixnets.

- There is no need to use `Pycryptodome` for this task. Using other Python facilities such as the `Counter` class (from
  `collections`) might be helpful to keep your answer short (but not necessary).

- The trace provided is a list of tuples `[(Senders, Receivers)]`. Each item of the list represents one round of the
  anonymity system, the senders observed sending in this round, and the receivers observed receiving. The identifiers of
  the senders / receivers are just small integers.

- Your task is to complete the function `analyze_trace` to return the identifiers of a number of receivers that are the
  friends of the target. Friends are any receivers that have received messages from the target. The number of friends
  sought is provided as `target_number_of_friends`, and the identifier of the target sender is provided as `target` (by
  default 0). You must return the list of receivers that Alice is sending messages to.

- Do study the function `generate_trace` that simulates a very simple anonymity system. It provides a good guide as to
  the types of data in the trace and their meaning, as well as a model you analysis can be based on.

- Remember the insight from the Statistical Disclosure Attack: anonymity systems provide imperfect privacy. This is
  mainly due to the fact that when a target is sending its small number of contacts are more likely to be receiving than
  other users. You will need to turn this insight into an algorithm that finds those contacts.

- As this is a statistical attack, it is not expected to produce an exact result with each instance. The tests expect a
  success rate of at least 2/3 in correctly identifying the full list of friends to pass.

## TASK Q1 and Q2 -- Answer the questions with reference to the code you wrote. \[1 point\]

- Please include these as part of the Code file submitted, as a multi-line string, where the `TODO` indicates.
