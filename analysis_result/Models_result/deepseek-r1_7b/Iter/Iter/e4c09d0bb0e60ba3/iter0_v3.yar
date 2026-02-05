rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 ?? ?? ?? 8B 45 53 }
        $pattern1 = { E9 B5 FC 74 00 01 8B ?? 26 C7 8D F8 FF 8C 75 0E 00 C0 8D 8D F8 FE F6 01 01 33 DB }
        $pattern2 = { E8 74 00 01 8B ?? ?? ?? ?? ?? FF 15 88 A0 2C 11 }

    condition:
        any of them
}