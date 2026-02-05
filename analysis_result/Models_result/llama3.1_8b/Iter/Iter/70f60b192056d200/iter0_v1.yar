rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? FF 75 08 }
        $pattern1 = { C1 E8 08 A8 01 75 ?? C1 E8 08 }
        $pattern2 = { 83 F8 01 74 ?? 64 A1 ?? ?? }

    condition:
        any of them
}