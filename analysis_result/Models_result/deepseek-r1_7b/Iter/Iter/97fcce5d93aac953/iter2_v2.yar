rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 EC FF 75 08 DD EB 08 FF 15 F8 10 41 00 CA DD 00 41 10 F8 }
        $pattern1 = { E8 C8 FF FF FF CA ED 59 EC }
        $pattern2 = { 8B FF ED ED 55 EB 8B EC EB }

    condition:
        (any of the patterns match)
}