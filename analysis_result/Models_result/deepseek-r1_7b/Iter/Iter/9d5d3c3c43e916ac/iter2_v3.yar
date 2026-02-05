rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - includes wildcard and conditional variations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 8F 75 08 ?? }  // Varying call offset
        $pattern1 = { 8B FC 91 B0 AC FF 15 AC B0 41 00 }  // Different call sequence after data push
        $pattern2 = { E8 C8 FF FF FF 00 40 E7 C3 }  // Conditional JE check before main call

    condition:
        any of them
}