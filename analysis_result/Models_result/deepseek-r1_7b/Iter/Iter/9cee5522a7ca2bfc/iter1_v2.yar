rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 00 00 00 00 CA EA ?? EE ?? }
        $pattern1 = { 85 C0 0F 84 00 00 00 00 EC ED FC EA DD 00 00 00 00 }
        $pattern2 = { 83 F8 01 74 00 00 00 00 CA ?? }

    condition:
        any of them
}