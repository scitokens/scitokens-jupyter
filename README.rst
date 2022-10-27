SciTokens Token Management Service for Jupyter
==============================================


Installation
------------

Use ``pip`` to install this package directly from this repository::

    python3 -m pip install git+https://github.com/scitokens/scitokens-jupyter.git@<ref>

In most cases, replace ``<ref>`` with the `tag for a specific version`_::

    python3 -m pip install git+https://github.com/scitokens/scitokens-jupyter.git@1.0.0

.. _tag for a specific version: https://github.com/scitokens/scitokens-jupyter/tags


Configuration
-------------

The default location for the configuration file is ``/etc/scitokens/jupyterhub_service.yaml``.

Its structure is defined by the class ``SecretServiceConfig`` in `<scitokens/jupyter/token_service.py>`_.
