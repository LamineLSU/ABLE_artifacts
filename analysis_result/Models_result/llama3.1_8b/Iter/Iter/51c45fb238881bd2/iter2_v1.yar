rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 59 E8 ?? ?? ?? ?? FF 45 E8 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 59 59 }
        $pattern2 = { FF 45 E8 83 7D E8 14 0F 82 BE 20 00 00 }

    condition:
        any of them
}