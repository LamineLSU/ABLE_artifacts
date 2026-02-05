rule Malware_Evasion_Bypass {
    meta:
        description = "Malware evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern1 = { 55 8B EC 83 EC 48 53 56 57 74 03 E8 ?? ?? ?? ?? 74 }
        $pattern2 = { E8 ?? ?? ?? FF 74 03 75 01 E8 ?? ?? ?? ?? }
        $pattern3 = { FF 15 ?? ?? ?? ?? 0F B6 42 4D EB 12 53 57 56 }

    condition:
        any of them
}