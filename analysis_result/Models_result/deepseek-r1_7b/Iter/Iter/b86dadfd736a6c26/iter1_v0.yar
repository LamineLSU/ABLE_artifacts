rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F3 0A 0A 05 0A E0 00 41 09 DA }
        $pattern1 = { E8 2C D0 0E C0 0F 03 E0 00 41 09 DC }
        $pattern2 = { E8 54 00 CA 00 41 0A 1E }

    condition:
        any of them
}