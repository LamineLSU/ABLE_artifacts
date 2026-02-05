rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 52 8B 16 50 50 51 FF D2 }
        $pattern1 = { 5E 5D C3 9A 98 2A 85 34 16 0F }
        $pattern2 = { 8B 45 08 8B 48 14 56 6A 35 6A 00 51 }

    condition:
        any of them
}