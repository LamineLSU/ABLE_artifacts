rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting specific code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 25 ???? } # Represents a call with known opcode and value
        $pattern1 = { 0F 84 ?? ?? ?? ?? } # Conditional jump near a known address
        $pattern2 = { E8 C8 ???? } # Another potential target instruction

    condition:
        any of them
}