rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted conditional exit check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF 59 EC }
        $pattern1 = { FF 75 08 DD EB 08 }
        $pattern2 = { FF 15 AC B0 41 00 CA DD 00 41 B0 AC }

    condition:
        any of them
}