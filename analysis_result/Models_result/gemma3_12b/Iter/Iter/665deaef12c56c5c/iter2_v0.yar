rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 C8 FF FF FF 59 }
        $pattern1 = { 83 F8 01 74 12 8B 4D }
        $pattern2 = { FF 15 AC B0 41 00 }

    condition:
        any of them
}