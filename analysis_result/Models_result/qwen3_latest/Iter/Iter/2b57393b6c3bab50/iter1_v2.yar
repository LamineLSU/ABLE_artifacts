rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? } // CALL instruction with wildcard address
        $pattern1 = { 8B 40 68 C1 E8 08 A8 01 75 10 } // MOV/SHR/TEST/JNE sequence
        $pattern2 = { 6A 00 FF 15 ?? ?? ?? ?? } // PUSH/CALL pattern before exit

    condition:
        any of them
}