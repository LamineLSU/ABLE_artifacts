rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 ?? ?? ?? ?? C1 E8 08 75 10 }
        $pattern1 = { C9 C3 C0 B8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
        $pattern2 = { FF 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? C3 }

    condition:
        any of them
}