rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 0F 83 03 C3 8B 4D FC E9 B5 FC F0 ?? ?? ?? ?? FF 15 88 A0 }
        $pattern1 = { 85 C0 74 12 0F 83 BA 04 01 00 00 8D 43 01 E8 E3 FA F0 ?? ?? ?? ?? FF 15 88 A0 }
        $pattern2 = { 85 C0 74 12 0F 83 6A 40 53 5B ?? ?? ?? ?? FF 15 88 A0 }

    condition:
        any of them
}