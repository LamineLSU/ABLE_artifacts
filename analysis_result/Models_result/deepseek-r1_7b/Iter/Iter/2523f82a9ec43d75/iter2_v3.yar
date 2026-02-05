rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting early exits"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FE FF }
        $pattern1 = { E8 EC 01 74 09 FE CC }
        $pattern2 = { BA 5D BA AF E0 5F }

    condition:
        any of them
}