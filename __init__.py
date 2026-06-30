# This file is part s3 module for Tryton.
# The COPYRIGHT file at the top level of this repository contains
# the full copyright notices and license terms.
from trytond.pool import Pool

from .s3 import Cron, FileStoreS3

__all__ = ['FileStoreS3', 'register']

def register():
    Pool.register(
        Cron,
        module='s3', type_='model')
