rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - improved based on trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 18 00 0D 61 7A 85 C0 00 0D 61 7C 74 12 00 0D 61 7E 6A 5B 00 0D 61 80 5A 00 0D 61 81 E8 CE 00 0D 61 90 0F 84 }
        $pattern1 = { 22 01 29 61 7A 85 C0 01 29 61 7C 74 12 01 29 61 7E 6A 5B 01 29 61 90 }
        $pattern2 = { 16 00 0D 61 BE E8 BE 00 0D 61 C1 53 00 0D 61 92 00 0D 61 92 }

    condition:
        any of them
}