rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific calls and conditionals"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { E9 B5 FC ?? 00 D0 61 90 ?? }

    condition:
        any of them
}