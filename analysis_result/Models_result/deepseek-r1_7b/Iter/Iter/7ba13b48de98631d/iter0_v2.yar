rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF CE FF 15 2C A1 23 01 }  
        $pattern1 = { 8B FF 55 EC FF FF 75 08 E8 C8 FF FF FF }
        $pattern2 = { 6A 5B FF 75 08 E8 C8 FF FF FF }
    condition:
        any of them
}