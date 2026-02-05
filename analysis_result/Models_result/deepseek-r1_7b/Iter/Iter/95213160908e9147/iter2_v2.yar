rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific and precise"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5A 00 00 00 5B EA AD EE }
        $pattern1 = { E8 74 FA FF FF CD BE EE CE CA }
        $pattern2 = { 3D 00 10 00 EC FC CA EE CE }

    condition:
        any of them
}