# defender2db

Download and parse Microsoft Defender Antivirus signatures into a searchable SQLite database. The project includes Lua parsing and a web interface for searching threats. It was originally based on [defender2yara](https://github.com/t-tani/defender2yara/).

Live at [defendersearch.r00ted.ch](https://defendersearch.r00ted.ch)

This project is a work in progress.

Microsoft ASR rules are in [result/asr_rules](https://github.com/dobin/defender2db/tree/main/result/asr_rules).
All 50'000 LUA scripts are in [result/lua](https://github.com/dobin/defender2db/tree/main/result/lua).

Data available at [defender2db_data](https://github.com/dobin/defender2db_data)


## Installation using `uv`

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if it is not already installed.

2. Clone this repository:

```sh
git clone https://github.com/dobin/defender2db.git
```

3. Move to the cloned directory:

```sh
cd defender2db
```

4. Create the project environment and install dependencies:

```sh
uv sync
```

On Debian/Ubuntu, `libarchive-dev` may also be required:
```
sudo apt install libarchive-dev
```


## Usage

### Download / Update virus definition

Download current Defender Signatures (VDM) into `cache/engine` and `cache/vdm`:

```sh
uv run defender2db --download
```

Result:
```
$ ls -l cache/engine/ cache/vdm/
cache/engine/:
drwxr-xr-x 2 dobin dobin 4096 Nov 21 09:05 1.1.25100.9002

cache/vdm/:
drwxr-xr-x 4 dobin dobin 4096 Nov 21 09:05 1.441
```


### Virus definitions to SQL DB

Convert to `./cache/threats.db` SQLite DB. File will be overwritten!
```sh
uv run defender2db --convert
```

Display first few entries of the sqlite db:

```sh
uv run python tools/dbtest.py
```


### Web Application

Start web server to search and browse the definitions: 

```sh
$ uv run python web.py
defender2db web interface
Listen on: 0.0.0.0 5002
 * Serving Flask app 'web'
 * Debug mode: off
```


### ASR rules

Get the ASR rules into `rules/`:

```sh
uv run defender2db --asr
```


## Pickle Cache (only for testing)

Convert VDM to a mega pickle `cache/mpas.vdm.pickle` and `cache/mpav.vdm.pickle`: 

```sh
uv run defender2db --topickle
```

Use the pickle instead of converting the VDM (can save a little bit of time):

Also: Convert to a mega pickle: 
```sh
uv run defender2db --convert --frompickle
```



## Original Acknowledgments / Reference by defender2yara

This project would not have been possible without the valuable resources and insights provided by the following:

- **GitHub - commial/experiments** and **Windows Defender: Demystifying and Bypassing ASR by Understanding the AVS Signatures**: A special thanks to the author of the [commial/experiments](https://github.com/commial/experiments) repository on GitHub and the insightful paper [Windows Defender: Demystifying and Bypassing ASR by Understanding the AVS Signatures](https://i.blackhat.com/EU-21/Wednesday/EU-21-Mougey-Windows-Defender-demystifying-and-bypassing-asr-by-understanding-the-avs-signatures.pdf), presented at Black Hat Europe 2021. His work and research have significantly aided our understanding of various aspects of antivirus signatures and provided deep insights into the workings of Windows Defender signatures.

- **GitHub—taviso/loadlibrary**: A special thanks to Tavis Ormandy's repository [loadlibrary] (https://github.com/taviso/loadlibrary) on GitHub. This repository provided great insights into Microsoft Defender and was an entry point for reversing `msmpeng.dll`.

- **Retooling Blog**: We also appreciate the author of the Retooling blog for their detailed article [An Unexpected Journey into Microsoft Defender's Signature World](https://retooling.io/blog/an-unexpected-journey-into-microsoft-defenders-signature-world). Their exploration and documentation of Microsoft Defender's signature mechanisms have been invaluable to this project.

- **Threat Name Definitions**: We acknowledge Microsoft for their detailed [Threat Name Definitions](https://learn.microsoft.com/en-us/defender-xdr/malware-naming?view=o365-worldwide). This documentation has been essential in understanding the malware naming conventions used by Microsoft Defender.

Thank you to all these sources for contributing to the field and sharing their knowledge with the community.
