rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 53 }
        $pattern1 = { FF 15 AC B0 41 00 59 53 FF 15 ?? B0 41 00 }
        $pattern2 = { E8 ?? ?? E0 D0 C0 00 CC 55 }

    condition:
        any of them
}