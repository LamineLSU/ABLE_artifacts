rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0D 0C 38 AB 22 3D 99 EC 6D 6B } // OR/CMP evasion check
        $pattern1 = { 8D B0 74 0C 00 00 56 E8 44 09 00 00 } // LEA/PUSH/CALL sequence
        $pattern2 = { FF D2 5E 5D C3 } // API call cleanup

    condition:
        any of them
}