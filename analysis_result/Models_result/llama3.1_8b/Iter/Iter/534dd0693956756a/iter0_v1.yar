rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF ?? ?? ?? A0 F1 42 00 }
        $pattern1 = { C1 E8 ?? ?? EA 08 }
        $pattern2 = { 64 A1 ?? ?? ?? EA DD 00 00 00 30 }

    condition:
        any of them
}