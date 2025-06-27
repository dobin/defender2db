

            #lua_fixed = fixup_lua_data(sig.sig_data[lua_header_offset:])
            #if lua_fixed is not None:
            #    filename_out = os.path.join("rules", "lua_{}.lua".format(n))
            #    open(filename_out, "wb").write(lua_fixed)

        #if threat.category_id == 43:
        #    print("ASR??")



        #if b"\25\x19\x00\x00" in sig.sig_data:
        #    print(f"ASR: {n} {threat.threat_name} ({threat.threat_id}) -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
        
         #print(f"ASR: {n} {threat.threat_name} ({threat.threat_id}) -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
        #print("{}:  {}".format(
        #    idx,
        #    sig.sig_data[0:32].hex()
        #))
        #if idx > 0:
        #    print("IDX: {}".format(idx))

       if False and threat.has_lua_signature():
            l = len(threat.get_lua_signatures())
            print(f"{n} {threat.threat_name} ({threat.threat_id}) #:{l} -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
            #print("  Lua num: {}".format(len(threat.get_lua_signatures())))
            
            #print("{}: {} ({}) with luas: {}".format(
            #    n,
            #    threat.threat_name,
            #    threat.threat_id,
            #    l
            #))
            all_lua += l

            # !InfrastructureShared (2147483632) with luas: 51118

            if False:
                i = 0
                for lua in threat.get_lua_signatures():
                    filename = "lua/defender_lua_{}_{}.bin".format(n, i)
                    # write to file
                    with open(filename,"wb") as f:
                        f.write(lua.sig_data)
                    i += 1

    # Signatures only
    if False:
        signatures = vdm.get_signatures()
        for sig in signatures:
            if b"\25\x19\x00\x00" in sig.sig_data:
                print(f"ASR: ")
            

    # Luas (signatures)
    if False:
        luas: List[LuaSig] = vdm.get_luas()
        n = 0
        for lua in luas:
            if n > 100:
                break

            # offset of Lua header
            lua_header_offset = lua.sig_data.find(b'\x1bLuaQ')

            print("Lua {}: ThreatID: {} CategoryID: {}  TypeID: {}  Offset: {}  ThreatName: {}".format(
                n,
                lua.threat_id,
                lua.category_id,
                lua.type_id,
                lua_header_offset,
                lua.threat_name,
            ))

            filename = "lua/defender_lua_{}.bin".format(n)
            # write to file
            with open(filename,"wb") as f:
                f.write(lua.sig_data)

            # find offset of Lua header
            #lua_header_offset = threat.sig_data.find(b'\x1bLuaQ')
            #if lua_header_offset != 8:
            #    print("Lua header offset is not 8: {}".format(lua_header_offset))
            #parse_data(threat.sig_data[lua_header_offset:], filename) # skip header

            n += 1

    # Threats (with several signatures)
    if True:
        threats = vdm.get_threats() # originial code
        #threats = vdm.get_signatures()  # original working mine

        progress_bar = tqdm(
                total=len(threats),
                unit='threat',
                bar_format='{l_bar}{bar:20}{r_bar}',
                colour='green',
                desc="Converting signatures",
                leave=False)

        n = 0
        all_lua = 0
        for threat in threats:
            for sig in threat.signatures:
                if len(sig.sig_data) < 42:
                    continue
                idx = sig.sig_data.find(b'-')
                if idx == -1:
                    continue
                #print(f"ASR: {n} {threat.threat_name} ({threat.threat_id}) -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
                #print("{}:  {}".format(
                #    idx,
                #    sig.sig_data[0:32].hex()
                #))
                #if idx > 0:
                #    print("IDX: {}".format(idx))
                if sig.sig_data[16] == 0x2d and sig.sig_data[idx+5] == 0x2d and sig.sig_data[idx+5+5] == 0x2d:
                    if sig.sig_data[8:8+4] == b"CVE-":
                        continue
                    print(f"ASR: {n} {threat.threat_name} ({threat.threat_id}) -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
                    print("     {}".format(
                        sig.sig_data[8:8+36]
                    ))
                #if b"\25\x19\x00\x00" in sig.sig_data:
                #    print(f"ASR: {n} {threat.threat_name} ({threat.threat_id}) -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
            
            if False and threat.has_lua_signature():
                l = len(threat.get_lua_signatures())
                print(f"{n} {threat.threat_name} ({threat.threat_id}) #:{l} -  TC:{threat.category_id} TT:{threat.threat_type} TP:{threat.threat_platform} TF:{threat.threat_family} TV:{threat.threat_variant}")
                #print("  Lua num: {}".format(len(threat.get_lua_signatures())))
                
                #print("{}: {} ({}) with luas: {}".format(
                #    n,
                #    threat.threat_name,
                #    threat.threat_id,
                #    l
                #))
                all_lua += l

                # !InfrastructureShared (2147483632) with luas: 51118

                if False:
                    i = 0
                    for lua in threat.get_lua_signatures():
                        filename = "lua/defender_lua_{}_{}.bin".format(n, i)
                        # write to file
                        with open(filename,"wb") as f:
                            f.write(lua.sig_data)
                        i += 1

            n += 1

            #yara_rules = YaraRule(threat,filesize_check=filesize_check,do_header_check=header_check)
            #if not yara_rules:
            #    continue
            #for yara_rule in yara_rules.generate_rules():
            #    try:
            #        yara.compile(source=yara_rule)
            #    except yara.SyntaxError as e:
            #        logger.warn(f"Failed to convert {threat.threat_name}: {str(e)}")
            #        logger.debug("\n"+yara_rule)
            #        continue
            #    results[threat].append(yara_rule)
            #    rule_count += 1
            progress_bar.update(1)

        progress_bar.close()

    #print("---------------------------> {}".format(all_lua))


        def has_lua_signature(self) -> bool:
        for sig in self.signatures:
            if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
                return True
        return False




import os
def signatures_downloaded(cache) -> bool:
    cache_path = os.path.join('cache', 'vdm')
    return os.path.exists(cache_path)


    @staticmethod
    def parse_luas(database:List[BaseSig]) -> List[LuaSig]:
        luas = []

        # parse
        # progress bar setup
        progress_bar = tqdm(
                total=len(database),
                unit='threats',
                bar_format='{l_bar}{bar:20}{r_bar}',
                colour='green',
                desc="Parsing threats",
                leave=False)

        for sig in database:
            # Lua stuff
            if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
                luas.append(sig)

            progress_bar.update(1)

        progress_bar.close()

        return luas




            # Lua stuff
            if sig.sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
                #print("Add lua signature to threat {}".format(threat.threat_name))
                #threat.add_signature(sig)
                if False:
                    with open("lua/all/defender_lua_{}.bin".format(n), "wb") as f:
                        f.write(sig.sig_data)

            n += 1