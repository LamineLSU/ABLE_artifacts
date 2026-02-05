rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns targeting sandbox detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE 5A E8 25 05 00 00 0F 84 33 FD FF FF FF 15 C7 EC EB FF 67 }
        $pattern1 = { 8B CE 5A E8 C8 FF FF FE FF 01 38 A9 BC 00 00 00 00 00 00 01 38 A9 BC 00 00 }
        $pattern2 = { FF 75 08 FF 15 AC B0 41 01 8B E5 E8 6A 00 00 00 00 00 00 00 00 00 00 }

    condition:
        any of them
}