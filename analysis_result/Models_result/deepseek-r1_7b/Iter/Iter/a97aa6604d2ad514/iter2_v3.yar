rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - target specific exit handlers"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5B E8 43 8B EC }
        $pattern1 = { 5E C3 }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 } // Example from Strategy C
    condition:
        any of them
}