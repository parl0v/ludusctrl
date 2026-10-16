# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Josip Parlov (@parl0v). See NOTICE for the attribution terms.
"""Single source of the PC receiver's version.

The installer, the frozen exe's version resource and the desktop UI all read
this, so bumping a release means changing exactly one line.
"""

VERSION = "1.2"
