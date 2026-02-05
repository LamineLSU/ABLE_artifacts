rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for CALL instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 B8 3A F6 E8 ?? }
        $pattern1 = { FF 15 B8 3A 07 ?? ?? . }
        $pattern2 = { FF 15 B8 38 EC 88 }

    condition:
        any of them
}