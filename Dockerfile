# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM busybox

COPY attest /bin/attest

CMD ["/bin/attest"]