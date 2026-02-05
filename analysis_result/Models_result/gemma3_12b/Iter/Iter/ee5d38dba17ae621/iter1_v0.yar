rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D }
        $pattern1 = { 8B 45 08 8B 48 14 56 6A 35 }
        $pattern2 = { 8B 55 14 8B 45 10 8B 4D 0C }

    condition:
        any of them
}