rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E 85 C0 74 0E }
        $pattern1 = { E8 89 E0 FF FF 85 C0 74 0E }
        $pattern2 = { FF 15 14 28 43 00 85 C0 6A 00 }

    condition:
        any of them
}