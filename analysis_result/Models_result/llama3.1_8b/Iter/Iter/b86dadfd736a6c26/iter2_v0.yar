rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // concrete bytes from the original trace
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 } // concrete comparison value and conditional logic
        $pattern2 = { E8 2C 01 00 00 6A 00 } // wildcard for CALL/JMP offset, followed by concrete bytes

    condition:
        any of them
}