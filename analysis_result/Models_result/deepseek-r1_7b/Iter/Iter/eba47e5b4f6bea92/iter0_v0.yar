rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting memory/stack jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 47 02 FF 15 2C A1 30 00 } // Represents a conditional jump XOR and call
        $pattern1 = { 6A 40 BA 21 05 DC 47 03 FF 15 2C A1 30 00 } // Shows a complex jump sequence
        $pattern2 = { 8B FF EC 43 0F 84 75 08 5B 6E 20 01 3C 0D ?? } // Includes multiple jumps and calls

    condition:
        any of them
}