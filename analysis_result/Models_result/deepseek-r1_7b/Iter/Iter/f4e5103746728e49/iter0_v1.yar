rule Bypass_Evasion {
    meta:
        description = "Evasion bypass analysis of ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 3C 0A F8 FE FF ?? 74 12 ?? ?? EA EA DC DA FA AD CA }
        $pattern1 = { 6A 5B 5A 8B CE E8 4D 1F 5E ?? ?? ?? CA }
        $pattern2 = { FF C8 F9 FE 00 74 1B 30 00 FF F8 FE FF ?? ?? ?? CA DD EE AD }

    condition:
        any of them
}