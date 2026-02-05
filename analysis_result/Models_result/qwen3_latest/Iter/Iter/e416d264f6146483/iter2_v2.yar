rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? FD FF ?? 83 C4 20 68 B8 0B 00 00 }  // Call to check function, add esp, push value
        $pattern1 = { FF 15 B0 62 45 00 E9 ?? }               // Call to Sleep, followed by jmp
        $pattern2 = { 83 C4 20 FF 15 70 62 45 00 }            // Add esp, call to ExitProcess

    condition:
        any of them
}