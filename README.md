![PhoenixNAP Logo](https://phoenixnap.com/wp-content/themes/phoenixnap-v2/img/v2/logo.svg)
# docker-machine-driver-phoenixnap
A PhoenixNAP Control Plane integration for Docker Machine.

The driver code is implemented and tested with version 0.5.2 of Docker Machine.  The current Docker Machine driver:
  - Depends on the SDK
  - Communicate with the docker-machine binary
  - Emits debugging statements with API request/response details
  - Queries PNCP for machine status
  - Creates virtual machines using known OS templates
  - Assigns public IP addresses to created virtual machines
  - Maintains a local repository of configuration information
