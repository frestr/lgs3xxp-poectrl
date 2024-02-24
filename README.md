# LGS3XXP PoE Control

Manage the state of of Power-over-Ethernet (PoE) ports on Linksys LGS3XXP smart switches
(LGS308P, LGS318P, LGS326P) -- without having to use the Web UI.

> [!NOTE]
> Only the LGS308P (8-port) model has been tested. Feel free to make a new issue on GitHub if you
> have the LGS318P or LGS326P models and they don't seem to work with `poectrl`.

## Setup

Clone the git project:

```sh
git clone https://github.com/frestr/lgs3xxp-poectrl.git
cd lgs3xxp-poectrl
```

Set up a Python virtual environment:

```sh
virtualenv venv
source venv/bin/activate
```

Install the package:

```sh
pip install .
```

Create a configuration file at `~/.config/poectrl/config.yaml` and fill in the hostname of your
switch, together with the switch's username and password (labels are optional):

```yaml
hostname: 192.168.0.1
username: admin
password: admin
#labels:
#  1: foo
#  2: bar
#  3: baz
```

> [!TIP]
> If you run `poectrl` without creating a configuration file first, a sample configuration will be
> created for you that you can then populate with your data.

Finally, test that everything works:

```sh
poectrl --status
```

> [!IMPORTANT]
> Your switch must have the HTTPS service enabled (In the Web UI:
> _Configuration > Security > Management Security > User Access & Accounts > HTTPS Service_).
> HTTP (without TLS) and Telnet is not supported.

## Usage

```console
$ poectrl --help
usage: poectrl [-h] [-v] [-s] [-p PORT_NUM | -l PORT_LABEL] [-e | -d | -c]

Manage the state of PoE ports on a LGS3XXP switch

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output
  -s, --status          Print current status of PoE ports. If provided together with -e|-d|-c, will
                        print status after update.
  -p PORT_NUM, --port PORT_NUM
                        Port number to operate on.
  -l PORT_LABEL, --label PORT_LABEL
                        Port label to operate on
  -e, --enable          Enable power on the specified port
  -d, --disable         Disable power on the specified port
  -c, --cycle           Power cycle the specified port
```

### Examples

> [!NOTE]
> Communicating with the switch can be quite slow. Wait times of 5-15 seconds per command is to be
> expected.

List port statuses:

```console
$ poectrl --status
Port Num          PoE Status        Power Output      Operation         Label
--------          ----------        ------------      ---------         -----
1                 Enabled           0                 Searching         foo
2                 Enabled           0                 Searching         bar
3                 Enabled           3000              Delivering Power  baz
4                 Enabled           0                 Searching
5                 Enabled           0                 Searching
6                 Enabled           4400              Delivering Power
7                 Enabled           0                 Searching
8                 Enabled           0                 Searching
```

Disable a port by port number, followed up by a status listing:

```console
$ poectrl --port 3 --disable --status
Port Num          PoE Status        Power Output      Operation         Label
--------          ----------        ------------      ---------         -----
1                 Enabled           0                 Searching         foo
2                 Enabled           0                 Searching         bar
3                 Disabled          0                 Disabled          baz
4                 Enabled           0                 Searching
5                 Enabled           0                 Searching
6                 Enabled           4200              Delivering Power
7                 Enabled           0                 Searching
8                 Enabled           0                 Searching
```

Enable a port by specifying its label:

```console
$ poectrl --label baz --enable --status
Port Num          PoE Status        Power Output      Operation         Label
--------          ----------        ------------      ---------         -----
1                 Enabled           0                 Searching         foo
2                 Enabled           0                 Searching         bar
3                 Enabled           0                 Powering Up       baz
4                 Enabled           0                 Searching
5                 Enabled           0                 Searching
6                 Enabled           3700              Delivering Power
7                 Enabled           0                 Searching
8                 Enabled           0                 Searching
```

Power cycle a port:

```console
$ poectrl --port 6 --cycle
```

## Uninstalling

1. Uninstall the package:
   ```sh
   pip uninstall poectrl
   ```
2. Remove the auxilliary files created during runtime:
   ```sh
   rm -r ~/.config/poectrl ~/.cache/poectrl
   ```