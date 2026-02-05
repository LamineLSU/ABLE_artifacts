rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 FF FF FF FF }
        $pattern1 = { 8B CE 05 5A E8 BE }
        $pattern2 = { 3D 00 10 00 00 00 FF 82 }

    condition:
        any of them
}