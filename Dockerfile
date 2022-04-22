# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM busybox

COPY helloWorld /bin/helloWorld

CMD ["/bin/helloWorld"]