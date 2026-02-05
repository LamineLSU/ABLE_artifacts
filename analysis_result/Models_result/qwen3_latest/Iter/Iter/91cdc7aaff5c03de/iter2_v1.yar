rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 3D 86 0A 46 00 0F 85 C3 00 00 00 } // cmp + jne (evasion check)
        $pattern1 = { FF 15 DC 91 44 00 } // call DeleteFileW (API interaction)
        $pattern2 = { FF 15 9C 91 44 00 } // call ExitProcess (termination)

    condition:
        any of them
}