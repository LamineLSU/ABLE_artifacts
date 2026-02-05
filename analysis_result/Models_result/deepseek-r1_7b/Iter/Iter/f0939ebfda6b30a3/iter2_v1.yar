rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 0F 84 ?? ?? ?? ?? E8 ?? }
        $pattern1 = { 74 D2 0F 85 C0 ?? ?? ?? ?? FF 15 84 A0 41 01 }
        $pattern2 = { E8 01 45 C0 ?? ?? ?? ?? FF 15 84 A0 41 01 }

    condition:
        any of them
}