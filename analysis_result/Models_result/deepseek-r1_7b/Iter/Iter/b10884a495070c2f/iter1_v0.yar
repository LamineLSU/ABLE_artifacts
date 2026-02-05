rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit decisions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC EB E8 90 F6 FF FF CA 00 40 15 A0 74 C0 EA EA }
        $pattern1 = { FF 15 D8 90 AB 00 CA DD 00 AB B0 D8 74 B8 00 AB 39 FC E8 E0 FB FF FF DD 10 }
        $pattern2 = { FF 15 B8 90 AB 00 CA DD 00 AB 90 B8 74 2C 00 AB 43 FC E8 E0 FB FF FF DD 10 }

    condition:
        any of them
}