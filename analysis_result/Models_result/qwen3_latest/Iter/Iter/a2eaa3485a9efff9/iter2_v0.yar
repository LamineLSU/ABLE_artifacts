rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 6A 00 E8 ?? ?? ?? ?? } // Push-zero + call to ExitProcess
        $pattern1 = { E8 ?? ?? ?? ?? FF 25 EC 40 40 00 } // Call + jmp to exit handler
        $pattern2 = { FF 25 EC 40 40 00 } // Direct jmp to exit handler

    condition:
        any of them
}