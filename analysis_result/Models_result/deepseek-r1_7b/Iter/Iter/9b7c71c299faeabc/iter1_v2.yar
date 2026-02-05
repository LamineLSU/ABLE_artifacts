rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using identified call sequences and conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B F0 50 3C FF D9 }  
        $pattern1 = { 6A 40 50 85 C0 0F 84 }
        $pattern2 = { 6A 40 EC 00 8D 44 24 }

    condition:
        any of them
}