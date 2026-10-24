'use strict';
// The address the provisioning UI listens on (#850 review, exposure policy).
//
// Loopback unless WEBUI_BIND_ADDR says otherwise. This used to be
// `process.env.HOSTNAME`. Every container runtime sets HOSTNAME to the
// container's own name, so in a container the UI bound to the container
// address, reachable by anything on that network, without anyone opting in.
// A deployment that needs it reachable sets WEBUI_BIND_ADDR explicitly (and
// publishes the port to 127.0.0.1 or an SSH tunnel, never all interfaces).
const LOOPBACK = '127.0.0.1';

function bindAddress(env) {
  const v = (env.WEBUI_BIND_ADDR || '').trim();
  return v === '' ? LOOPBACK : v;
}

module.exports = { bindAddress, LOOPBACK };
