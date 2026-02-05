rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - First Call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 15 2C 64 45 00 }

    condition:
        any of them
}