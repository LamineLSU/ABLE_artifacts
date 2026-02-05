rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with earlier and specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { FF 15 AC B0 41 00 }
        $pattern2 = { 03 FC 8D 6A 79 7E }

    condition:
        any of them
}