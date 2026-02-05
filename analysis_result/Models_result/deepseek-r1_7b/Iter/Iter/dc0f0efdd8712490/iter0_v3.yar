rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B CE E8 25 05 00 00 03 C9 01 D2 }
        $pattern1 = { 85 C0 ?? ?? 0F 84 74 12 8B CE E8 4B 17 00 00 FF 75 08 00 33 D9 }
        $pattern2 = { 85 C0 ?? 0F 84 74 12 8B CE E8 E3 FA FF FF 8D 43 01 FF 75 08 00 FF D9 }

    condition:
        any of them
}