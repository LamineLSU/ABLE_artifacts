rule Bypass_Sample {
    meta:
        description = "Evasion bypass targeting 0015A12Ch"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 C8 FF FF FF FF 15 2C A1 2A 01 }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? }
        $pattern2 = { FF 75 08 33 CD EC B4 ?? ?? ?? ?? ?? }

    condition:
        any of them
}