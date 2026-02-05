rule EvasionBypass {
    meta:
        description = "Evasion bypass detection based on call address analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 40 ?? ?? 5B 8B CE E8 C8 FF FF FF 8C FF ?? ?? ?? ?? 33 D1 0F 84 FF 75 08 FF 75 08 2F 01 }
        $pattern1 = { 6A 40 ?? ?? 5B 8B EC E8 C8 FF FF FF 8C FF ?? ?? ?? ?? 33 D1 0F 84 FF 75 08 FF 75 08 2F 01 }
        $pattern2 = { 6A 40 ?? ?? 5B 8B CF E8 C8 FF FF FF 8C FF ?? ?? ?? ?? 33 D1 0F 84 FF 75 08 FF 75 08 2F 01 }

    condition:
        any of them
}