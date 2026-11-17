from typing import List,Dict,Tuple
import os
import sys
import shutil
from collections import Counter, defaultdict
from contextlib import nullcontext
from defender2yara.defender.dbthreat import DEFAULT_DATABASE
from defender2yara.database_build import build_database
from defender2yara.conversion import store_source
from packaging.version import Version

from defender2yara.defender.threat import Threat
from defender2yara.yara.rule import YaraRule, compile_yara_source
from defender2yara.defender.vdm import Vdm
from defender2yara.defender.download import get_latest_signature_vdm, download_latest_signature, parse_mpam_exe
from defender2yara.defender.luaparse import fixup_lua_data, lua_decompile, lua_disassemble, lua_decompile_data
from defender2yara.defender.lua_backend import load_lua_backend
from defender2yara.defender.signature import *
from defender2yara.util.utils import hexdump
from tqdm import tqdm
import logging

logger = logging.getLogger(__package__)

def clean_up_dir(path:str):
    if not os.path.exists(path):
        raise ValueError(f"Path does not exists: {path}")
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                os.remove(file_path)
            except Exception as e:
                logger.error(f"Failed to delete: {file_path}. Error: {e}")
        
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            try:
                shutil.rmtree(dir_path)
            except Exception as e:
                logger.error(f"Failed to delete directory: {dir_path}. Error: {e}")


def write_rules_to_single_file(path,filename,results:Dict[Threat,List[str]]):
    output = []
    for rules in results.values():
        output.extend(rules)
    # write result
    output_file = os.path.join(path,f"{filename}.yara")        
    with open(output_file,'w') as f:
        f.writelines(output)
        logger.info(f"Write YARA rules to {output_file}")


def write_rules_by_family(path,results:Dict[Threat,List[str]]):
    threat:Threat
    for threat,rules in results.items():
        output_dir = os.path.join(path,threat.threat_platform,threat.threat_type)
        if not threat.threat_family:
            output_file = os.path.join(output_dir,"misc.yara")
        else:
            output_file = os.path.join(output_dir,threat.threat_family+".yara")

        os.makedirs(output_dir, exist_ok=True)
        with open(output_file,'a') as f:
            f.writelines(rules)
    logger.info(f"Write YARA rules to {path}")


def parse_asr_entry(threat: Threat, n: int) -> int:
    for sig in threat.signatures:
        if len(sig.sig_data) < 42:
            continue
        idx = sig.sig_data.find(b'-')
        if idx == -1:
            continue

        # heuristics to find guid: xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if sig.sig_data[16] == 0x2d and sig.sig_data[idx+5] == 0x2d and sig.sig_data[idx+5+5] == 0x2d and sig.sig_data[idx+5+5+5] == 0x2d:
            # Remove fale positives which has the exact same format lol
            # CVE-2019-1652-1653-AD
            if sig.sig_data[8:8+4] == b"CVE-":
                continue

            print(f"ASR {n}: {threat.threat_name} ({threat.threat_id}) -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
            print("  GUID: {}".format(
                sig.sig_data[8:8+36]
            ))
            if threat.category_id != 43:
                # no issue, just print a warning
                print("  Unexpected Category ID: {}".format(threat.category_id))

            lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
            if lua_header_offset == -1:
                print("  No Lua header found in signature data.")
                continue
            if lua_header_offset != 45:
                # no issue, just print a warning
                print("  Lua header offset is not at expected position (45): {}".format(lua_header_offset))
            #print("Lua header offset: {}".format(lua_header_offset))

            # fixup lua data
            lua_fixed, error = fixup_lua_data(sig.sig_data[lua_header_offset:])
            if lua_fixed is None:
                logger.error(f"Failed to fixup Lua data for threat {threat.threat_name}: {error}")
                continue
            
            filename_out = os.path.join("rules", "asr_lua_{}.bin".format(n))
            open(filename_out, "wb").write(lua_fixed)
            n += 1
    return n

def parse_asr(vdm: Vdm):
    threats = vdm.get_threats()
    progress = False
    progress_bar: tqdm

    # make dir rules/asr_lua if not exists
    os.makedirs("rules/asr_lua", exist_ok=True)

    if progress:
        progress_bar = tqdm(
                total=len(threats),
                unit='threat',
                bar_format='{l_bar}{bar:20}{r_bar}',
                colour='green',
                desc="Converting signatures",
                leave=False)

    # Parse Threats to find ASR entries
    n = 0
    for threat in threats:
        if threat.threat_id == 2147483632: # !InfrastructureShared
            n = parse_asr_entry(threat, n)
        
        if progress:
            progress_bar.update(1)

    if progress:
        progress_bar.close()


def parse_sig_lua(vdm:Vdm, name: str):
    logger.info("Parsing Threat Lua signatures...")
    signatures = vdm.get_signatures()

    n = 0
    for sig in signatures:
        if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
            lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
            lua_data, error = fixup_lua_data(sig.sig_data[lua_header_offset:])
            if lua_data is None:
                logger.error(f"Failed to fixup Lua data for signature {n}: {error}")
                n += 1
                continue
            if lua_data is not None:
                # write file
                filepath = os.path.join("rules", "lua", name, "{}.bin".format(n))
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                #print("Write file raw: {}".format(filepath))
                with open(filepath, "wb") as f:
                    f.write(lua_data)

                # convert
                lua_disassembled = lua_decompile(filepath)

                # write disassembled lua to file
                filepath2 = filepath + ".txt"
                if lua_disassembled is not None:
                    with open(filepath2, "wb") as f:
                        f.write(lua_disassembled)

                    #print("Lua signature full written to: {}".format(filepath2))
                else:
                    #print("Lua signature only raw written to: {}".format(filepath2))
                    pass

            n += 1


def parse_threat_lua(vdm:Vdm):
    logger.info("Parsing Threat Lua signatures...")
    results:Dict[Threat,List[str]] = defaultdict(list)
    threats = vdm.get_threats()

    progress_bar = tqdm(
            total=len(threats),
            unit='threat',
            bar_format='{l_bar}{bar:20}{r_bar}',
            colour='green',
            desc="Converting signatures",
            leave=False)

    count = 0
    for threat in threats:
        print("Threat: {} ({}) - TC:{} TT:{} TP:{} TF:{} TV:{} -> {}".format(
            threat.threat_name,
            threat.threat_id,
            threat.category_id,
            threat.threat_type,
            threat.threat_platform,
            threat.threat_family,
            threat.threat_variant,
            len(threat.signatures)
        ))
        #for sig in threat.signatures:
        #    print("  Signature: {} ({})  Size:{}".format(
        #        sig.sig_type_id,
        #        sig.sig_type,
        #        sig.size
        #    ))


        if False:
            luas = []

            for sig in threat.signatures:
                if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
                    print("  Lua signature found: {}".format(sig.sig_name))

                    lua_header_offset = sig.sig_data.find(b'\x1bLuaQ')
                    lua_data, error = fixup_lua_data(sig.sig_data[lua_header_offset:])
                    if lua_data is None:
                        logger.error(f"Failed to fixup Lua data for threat {threat.threat_name}: {error}")
                        continue
                    if lua_data:
                        luas.append(lua_data)
                    else:
                        print("  Invalid Lua signature data found in threat: {}".format(threat.threat_name))

            print("  Lua signatures found: {}".format(len(luas)))
            if len(luas) != 0:
                # write file
                if False:
                    print("Lua Event: {} ({}) - TC:{} TT:{} TP:{} TF:{} TV:{}".format(
                        threat.threat_name,
                        threat.threat_id,
                        threat.category_id,
                        threat.threat_type,
                        threat.threat_platform,
                        threat.threat_family,
                        threat.threat_variant
                    ))

                # rules/[Exploit/Trojan/VirTool/...]
                filepath = os.path.join("rules", threat.threat_type)
                filepath = os.path.join(filepath, "lua")

                # rules/Exploit/Exploit:Win32/CVE-2015-2545.A
                # replace: space / : 
                threat_name = threat.threat_name.replace(" ", "_").replace("/", "_").replace(":", "_").replace("\\", "_")

                # create directory if not exists
                os.makedirs(os.path.dirname(filepath), exist_ok=True)

                n = 0
                for lua in luas:
                    fname = "{}_{}.bin".format(threat_name, n)
                    filepath = os.path.join(filepath, fname)

                    # raw
                    print("Write raw: {}".format(filepath))
                    with open(filepath, "wb") as f:
                        f.write(lua)

                    # convert
                    lua_disassembled = lua_decompile(filepath)
                    if lua_disassembled is not None:
                        with open(filepath + ".txt", "wb") as f:
                            f.write(lua)
                            f.write("Lua rule for {}\n".format(threat.threat_name).encode('utf-8'))
                            f.write("Threat ID: {}\n".format(threat.threat_id).encode('utf-8'))
                            f.write("Category ID: {}\n".format(threat.category_id).encode('utf-8'))
                            f.write("Threat Type: {}\n".format(threat.threat_type).encode('utf-8'))
                            f.write("Threat Platform: {}\n".format(threat.threat_platform).encode('utf-8'))
                            f.write("Threat Family: {}\n".format(threat.threat_family).encode('utf-8'))
                            f.write("Threat Variant: {}\n\n".format(threat.threat_variant).encode('utf-8'))
                            f.write(lua_disassembled.encode('utf-8'))
                            f.write(b"\n\n")
                n += 1

        progress_bar.update(1)

        count += 1

        if count == 100:
            break

    progress_bar.close()
    return results


def parse_threats_by_name(vdm:Vdm, search: str):
    logger.info("Parsing Threats for name: {}".format(search))
    threats = vdm.get_threats()
    for threat in threats:
        if search in threat.threat_name:
            print("Threat: {} ({}) - TC:{} TT:{} TP:{} TF:{} TV:{}  Sigs:{}".format(
                threat.threat_name,
                threat.threat_id,
                threat.category_id,
                threat.threat_type,
                threat.threat_platform,
                threat.threat_family,
                threat.threat_variant,
                len(threat.signatures)
            ))

            if True:
                for sig in threat.signatures:
                    print("  {} Signature: {} ({})  Size:{}".format(
                        threat.threat_name,
                        sig.sig_type_id,
                        sig.sig_type,
                        sig.size
                    ))
                    hexdump(sig.sig_data)


def generate_output(threat):
    lua_diagnostics, yara_diagnostics = [], []
    lua = get_lua_from_threat(threat, lua_diagnostics)
    yara_rules = get_yara_from_threat(threat, yara_diagnostics)
    has_lua = any(sig.sig_type == 'SIGNATURE_TYPE_LUASTANDALONE' for sig in threat.signatures)
    return {
        'lua': {'status': ('partial' if lua_diagnostics else 'generated') if lua else ('error' if has_lua else 'not_applicable'),
                'items': [item.decode('utf-8', errors='replace') if isinstance(item, bytes) else item for item in lua],
                'diagnostics': lua_diagnostics},
        'yara': {'status': ('partial' if yara_diagnostics else 'generated') if yara_rules else ('error' if yara_diagnostics else 'not_applicable'),
                 'items': yara_rules, 'diagnostics': yara_diagnostics},
    }


def convert_threats(vdm, connection, include_raw=False):
    return store_source(connection, vdm, include_raw=include_raw, generate=generate_output)


def log_unparseable_signatures(stats):
    logger.info('Unparseable signatures: %d', sum(stats.values()))
    for (sig_type, sig_type_id), count in sorted(
            stats.items(), key=lambda item: (-item[1], item[0][0])):
        logger.info('  %s (0x%02x): %d', sig_type, sig_type_id, count)


def get_lua_from_threat(threat:Threat, diagnostics=None) -> List[bytes]:
    lua_scripts = []
    diagnostics = diagnostics if diagnostics is not None else []
    for signature_index, sig in enumerate(threat.signatures):
        if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
            offset = getattr(sig, "offset", None)
            context = (
                f"threat={threat.threat_name!r} threat_id={getattr(threat, 'threat_id', 'unknown')} "
                f"signature_index={signature_index} (zero-based) "
                f"type={sig.sig_type} type_id={getattr(sig, 'sig_type_id', 'unknown')} "
                f"vdm_offset={hex(offset) if offset is not None else 'unknown'} "
                f"payload_size={len(sig.sig_data)} prefix_hex={sig.sig_data[:48].hex()}"
            )
            body = getattr(sig, "body", None)
            if body is None:
                body = sig.sig_data
            lua_header_offset = body.find(b'\x1bLuaQ')
            if lua_header_offset < 0:
                if getattr(sig, "body_format", None) == "mplua_headerless":
                    # A known variant whose instruction set the bundled
                    # decompiler does not implement.  This is not a parse
                    # failure, so do not emit one warning per record.
                    logger.debug("Unsupported headerless Lua body: %s", context)
                    diagnostics.append({'offset': offset, 'status': 'unsupported',
                                        'message': 'Headerless MpLua body'})
                    continue
                logger.warning("No Lua header: %s", context)
                diagnostics.append({'offset': offset, 'status': 'error', 'message': 'No Lua header'})
                continue
            lua_data = body[lua_header_offset:]
            lua_decompiled = lua_decompile_data(lua_data)
            if lua_decompiled is None or b'DECOMPILER ERROR' in lua_decompiled:
                logger.warning("Lua decompilation incomplete: %s lua_header_offset=%d; trying disassembly", context, lua_header_offset)
                diagnostics.append({'offset': offset, 'status': 'disassembly_fallback', 'message': 'Decompilation incomplete'})
                listing = lua_decompile_data(lua_data, disassemble=True)
                if listing is not None:
                    lua_decompiled = (lua_decompiled or b'') + b'\n-- Decompilation incomplete; bytecode disassembly follows.\n' + listing
                else:
                    logger.warning("Lua disassembly failed: %s lua_header_offset=%d", context, lua_header_offset)
            if lua_decompiled is not None:
                lua_scripts.append(lua_decompiled)

    return lua_scripts


def get_yara_from_threat(threat:Threat, diagnostics=None) -> List[str]:
    result = []
    diagnostics = diagnostics if diagnostics is not None else []

    yara_rules = YaraRule(threat,filesize_check="20MB",do_header_check=False)
    if len(yara_rules.rules) < len(threat.hstr_signatures):
        diagnostics.append({'status': 'omitted', 'message': 'Some string signatures could not produce a complete YARA rule'})
    if not yara_rules:
        return result

    for yara_rule in yara_rules.generate_rules():
        compiled, compile_error = compile_yara_source(yara_rule)
        if compiled is None:
            logger.warning(f"Failed to convert {threat.threat_name} to yara: {str(compile_error)}")
            diagnostics.append({'status': 'error', 'message': str(compile_error)})
            logger.debug("\n"+yara_rule)
            continue
        if compiled != yara_rule:
            diagnostics.append({'status': 'simplified',
                                'message': f'Hex alternatives simplified to compile: {compile_error}'})
            yara_rule = compiled
        result.append(yara_rule)

    return result


def covert_vdm_to_yara(vdm:Vdm,filesize_check:str,header_check:bool=False) -> Tuple[Dict[Threat,List[str]],int]:
    logger.info(f"Parsing signature database...")
    results:Dict[Threat,List[str]] = defaultdict(list)
    rule_count = 0
    # convert to yara rule
    threats = vdm.get_threats()

    progress_bar = tqdm(
            total=len(threats),
            unit='threat',
            bar_format='{l_bar}{bar:20}{r_bar}',
            colour='green',
            desc="Converting signatures",
            leave=False)

    for threat in threats:
        yara_rules = YaraRule(threat,filesize_check=filesize_check,do_header_check=header_check)
        if not yara_rules:
            continue
        for yara_rule in yara_rules.generate_rules():
            compiled, compile_error = compile_yara_source(yara_rule)
            if compiled is None:
                logger.warn(f"Failed to convert {threat.threat_name}: {str(compile_error)}")
                logger.debug("\n"+yara_rule)
                continue
            results[threat].append(compiled)
            rule_count += 1
        progress_bar.update(1)

    progress_bar.close()

    return results,rule_count


cache_dir = "cache"


def get_latest_engine_version(engine_path):
    versions = []
    for entry in os.listdir(engine_path):
        try:
            versions.append(Version(entry))
        except:
            continue
    return str(max(versions)) if versions else None

def get_latest_signature_version(vdm_path):
    major_minor_versions = []
    for entry in os.listdir(vdm_path):
        if os.path.isdir(os.path.join(vdm_path, entry)):
            try:
                major_minor_versions.append(Version(entry))
            except:
                continue
    if not major_minor_versions:
        return None

    latest_major_minor = str(max(major_minor_versions))
    sub_path = os.path.join(vdm_path, latest_major_minor)
    builds = []
    for entry in os.listdir(sub_path):
        try:
            builds.append(Version(entry))
        except:
            continue

    if not builds:
        return None

    latest_build = str(max(builds))
    return f"{latest_major_minor}.{latest_build}"


def main(args):
    signature_version:str = ""
    engine_version:str = ""

    if args.convert and not args.download:
        load_lua_backend()  # Validate before recreating the database.

    if args.download:
        logger.info("Downloading latest signature database")
        signature_version, engine_version, use_cache = download_latest_signature(cache_dir,proxy=args.proxy)
        logger.info(f"Written to: {cache_dir}")
        logger.info(f"  Latest Signature Version:{signature_version}")
        logger.info(f"  Latest Engine Version   :{engine_version}")
        return
    else:
        logger.info("Using existing signature database")
        signature_version = get_latest_signature_version(os.path.join(cache_dir,"vdm"))
        engine_version = get_latest_engine_version(os.path.join(cache_dir,"engine"))

        logger.info(f"  Latest Signature Version:{signature_version}")
        logger.info(f"  Latest Engine Version   :{engine_version}")

        if not signature_version:
            logger.error("No signature version found. Please download the latest signature database with --download option.")
            sys.exit(1)

    context = build_database(
        getattr(args, 'db', DEFAULT_DATABASE), signature_version=signature_version,
        engine_version=engine_version, include_raw=getattr(args, 'include_raw', False),
    ) if args.convert else nullcontext(None)

    unparseable = Counter()
    with context as connection:
        # iterate through mpav and mpas - each can take a lot of memory
        for name in ["mpav","mpas"]:
            vdm: Vdm = None

            major_version = ".".join(signature_version.split(".")[0:2])
            minor_version = ".".join(signature_version.split(".")[2:4])
            vdm_base_path = os.path.join(cache_dir,"vdm",major_version,'0.0')
            vdm_delta_path = os.path.join(cache_dir,"vdm",major_version,minor_version)
            base_file = os.path.join(vdm_base_path,name+"base.vdm")
            delta_file = os.path.join(vdm_delta_path,name+"dlta.vdm")

            logger.info(f"Loading base signature file: {base_file}")
            logger.info(f"Creating vdm from files: {vdm_base_path}")
            vdm = Vdm(base_file)
            if os.path.exists(delta_file):
                logger.info(f"Applying delta patch: {delta_file}")
                vdm.apply_delta_vdm(delta_file)
            # Parse the patched data, not the stale base-only signatures.
            vdm.parse_files()

            #logger.info(f"VDM Target signature version: {vdm.version}")
            #logger.info(f"VDM Target signature type   : {vdm.vdm_type}")

            if args.convert:
                # convert threats to database
                unparseable.update(convert_threats(vdm, connection, getattr(args, 'include_raw', False)))
            elif args.asr:
                # extract ASR entries
                parse_asr(vdm)
            else:
                # extract ASR entries - around 24
                #parse_asr(vdm)

                # extract all threats with LUA
                #parse_threat_lua(vdm)

                # extract all LUA - around 50k, including ASR
                #parse_sig_lua(vdm, name)

                # extract all threats
                #parse_threats(vdm, search="Bearfoos.A!ml")

                # find a threat
                #find = "Bearfoos.A"
                #logger.info(f"Searching for threats with name: {find}")
                #parse_threats(vdm, search=find)

                pass

    if args.convert:
        log_unparseable_signatures(unparseable)
    logger.info("Complete")
    sys.exit(0)
