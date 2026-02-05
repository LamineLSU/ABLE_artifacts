rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF FF 15 2C A1 13 01 ?? ?? }
        $pattern1 = { FF 15 2C A1 13 01 ?? ?? E8 C8 FF FF FF }
        $pattern2 = { FF 15 8C E1 2A 00 ?? ?? FF 15 2C A1 13 01 }

    condition:
        any of them
}