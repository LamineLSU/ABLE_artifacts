rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checking EAX test for bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF E8 C8 FF FF FF FF 75 08 FF 75 08 }
        $pattern1 = { E8 C8 FF FF FF FF 75 08 FF 75 08 55 00 }
        $pattern2 = { FF 75 08 FF 75 08 55 00 00 }

    condition:
        any of them
}