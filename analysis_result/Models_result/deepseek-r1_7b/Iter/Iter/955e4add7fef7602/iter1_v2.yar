rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple strategies"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 8B EC E8 C8 FF FF FF FF 75 08 DD EB 08 59 EC 75 08 }
        $pattern1 = { E8 C8 FF FF FF FF 75 08 DD EB 08 59 EC 75 08 FF 15 AC B0 41 00 }
        $pattern2 = { 6A 5A 8B CE E8 C8 FF FF FF FF 75 08 DD EB 08 59 EC 75 08 }

    condition:
        any of the above patterns matched
}