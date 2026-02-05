rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Bypass Out Instruction"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { E7 23 69 97 3B 36 55 8B EC }

    condition:
        any of them
}