rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with targeted conditional jumps and fixed calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 C7 5E EA EB 07 5D }
        $pattern1 = { F8 45 FC EA EB 0C 8B 4D F8 00 00 00 35 }
        $pattern2 = { 8B 45 AF CA 00 41 AF 60 74 }
    condition:
        any of them
}