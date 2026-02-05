rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? FF 15 2C A1 28 01 FF 15 88 A0 28 01 FF 15 2C A1 28 01 }
        $pattern1 = { 0F 84 ?? ?? ?? ?? 85 C0 74 07 FF 15 ?? ?? ?? ?? FF 15 88 A0 28 01 }
        $pattern2 = { E8 25 05 00 00 E8 74 FA FF FF FF 15 ?? ?? ?? ?? FF 15 2C A1 28 01 FF 15 88 A0 28 01 }

    condition:
        any of them
}