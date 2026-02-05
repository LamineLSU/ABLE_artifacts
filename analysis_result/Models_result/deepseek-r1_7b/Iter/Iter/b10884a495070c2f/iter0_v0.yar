rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 08 EA DD EB 08 50 EA 53 EB E8 EC F4 FF FF CA 00 40 14 10 83 C4 04 AD 04 }
        $pattern1 = { FF 74 24 10 DD 10 FF 74 24 14 DD 14 FF 74 24 18 DD 18 }
        $pattern2 = { E8 EC F4 FF FF CA 00 40 14 10 83 C4 04 AD 04 53 EB E8 E0 FB FF FF DD 10 FF 74 24 10 DD 10 }

    condition:
        any of them
}