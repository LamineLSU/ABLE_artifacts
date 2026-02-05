rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using stack and memory addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 84 33 C9 5A 8B CE E8 45 FF ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 53 ?? ?? ?? ?? 8B 45 5E 5C ?? ?? ?? ?? FF 75 08 5A 8B }
        $pattern1 = { 8B EC 5A 8B CE E8 25 00 00 00 00 C3 00 00 00 00 FF 74 07 74 07 ?? ?? ?? ?? FF 15 A5 00 00 00 00 8B 4D 5E FF FF FF FF }
        $pattern2 = { 6A 40 ?? ?? FF 75 08 E8 CE 1C 39 00 00 00 00 5F 00 00 00 00 8B 4D 5E FF FF FF FF FF 15 A5 00 00 00 00 8B 4D 5E FF FF }

    condition:
        any of them
}