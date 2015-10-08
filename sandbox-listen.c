/*****************************************************************
 * Copyright 2015 Rackspace, Inc.
 *
 * listen on a unix domain socket for incoming patches
 ****************************************************************/



#include <sys/socket.h>
#include <sys/un.h>
#include "sandbox.h"
